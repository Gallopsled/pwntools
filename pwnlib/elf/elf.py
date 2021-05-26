"""Exposes functionality for manipulating ELF files


Stop hard-coding things!  Look them up at runtime with :mod:`pwnlib.elf`.

Example Usage
-------------

.. code-block:: python

    >>> e = ELF('/bin/cat')
    >>> print(hex(e.address)) #doctest: +SKIP
    0x400000
    >>> print(hex(e.symbols['write'])) #doctest: +SKIP
    0x401680
    >>> print(hex(e.got['write'])) #doctest: +SKIP
    0x60b070
    >>> print(hex(e.plt['write'])) #doctest: +SKIP
    0x401680

You can even patch and save the files.

.. code-block:: python

    >>> e = ELF('/bin/cat')
    >>> e.read(e.address+1, 3)
    b'ELF'
    >>> e.asm(e.address, 'ret')
    >>> e.save('/tmp/quiet-cat')
    >>> disasm(open('/tmp/quiet-cat','rb').read(1))
    '   0:   c3                      ret'

Module Members
--------------
"""
from __future__ import absolute_import
from __future__ import division

import collections
import gzip
import mmap
import os
import re
import six
import subprocess
import tempfile

from six import BytesIO

from collections import namedtuple

from elftools.elf.constants import E_FLAGS
from elftools.elf.constants import P_FLAGS
from elftools.elf.constants import SHN_INDICES
from elftools.elf.descriptions import describe_e_type
from elftools.elf.elffile import ELFFile
from elftools.elf.gnuversions import GNUVerDefSection
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection
from elftools.elf.segments import InterpSegment

# See https://github.com/Gallopsled/pwntools/issues/1189
try:
    from elftools.elf.enums import ENUM_P_TYPE
except ImportError:
    from elftools.elf.enums import ENUM_P_TYPE_BASE as ENUM_P_TYPE

import intervaltree

from pwnlib import adb
from pwnlib import qemu
from pwnlib.asm import *
from pwnlib.context import LocalContext
from pwnlib.context import context
from pwnlib.elf.config import kernel_configuration
from pwnlib.elf.config import parse_kconfig
from pwnlib.elf.datatypes import constants
from pwnlib.elf.maps import CAT_PROC_MAPS_EXIT
from pwnlib.elf.plt import emulate_plt_instructions
from pwnlib.log import getLogger
from pwnlib.term import text
from pwnlib.tubes.process import process
from pwnlib.util import misc
from pwnlib.util import packing
from pwnlib.util.fiddling import unhex
from pwnlib.util.misc import align, align_down
from pwnlib.util.sh_string import sh_string

log = getLogger(__name__)

__all__ = ['load', 'ELF']

def _iter_symbols(sec):
    # Cache result of iter_symbols.
    if not hasattr(sec, '_symbols'):
        sec._symbols = list(sec.iter_symbols())
    return iter(sec._symbols)

class Function(object):
    """Encapsulates information about a function in an :class:`.ELF` binary.

    Arguments:
        name(str): Name of the function
        address(int): Address of the function
        size(int): Size of the function, in bytes
        elf(ELF): Encapsulating ELF object
    """
    def __init__(self, name, address, size, elf=None):
        #: Name of the function
        self.name = name

        #: Address of the function in the encapsulating ELF
        self.address = address

        #: Size of the function, in bytes
        self.size = size

        #: Encapsulating ELF object
        self.elf = elf

    def __repr__(self):
        return '%s(name=%r, address=%#x, size=%#x, elf=%r)' % (
            self.__class__.__name__,
            self.name,
            self.address,
            self.size,
            self.elf
            )

    def __flat__(self):
        return packing.pack(self.address)

    def disasm(self):
        return self.elf.disasm(self.address, self.size)

def load(*args, **kwargs):
    """Compatibility wrapper for pwntools v1"""
    return ELF(*args, **kwargs)

class dotdict(dict):
    """Wrapper to allow dotted access to dictionary elements.

    Is a real :class:`dict` object, but also serves up keys as attributes
    when reading attributes.

    Supports recursive instantiation for keys which contain dots.

    Example:

        >>> x = pwnlib.elf.elf.dotdict()
        >>> isinstance(x, dict)
        True
        >>> x['foo'] = 3
        >>> x.foo
        3
        >>> x['bar.baz'] = 4
        >>> x.bar.baz
        4
    """
    def __getattr__(self, name):
        if name in self:
            return self[name]

        name_dot = name + '.'
        name_len = len(name_dot)
        subkeys = {k[name_len:]: self[k] for k in self if k.startswith(name_dot)}

        if subkeys:
            return dotdict(subkeys)

        return getattr(super(dotdict, self), name)

class ELF(ELFFile):
    """Encapsulates information about an ELF file.

    Example:

        .. code-block:: python

           >>> bash = ELF(which('bash'))
           >>> hex(bash.symbols['read'])
           0x41dac0
           >>> hex(bash.plt['read'])
           0x41dac0
           >>> u32(bash.read(bash.got['read'], 4))
           0x41dac6
           >>> print(bash.disasm(bash.plt.read, 16))
           0:   ff 25 1a 18 2d 00       jmp    QWORD PTR [rip+0x2d181a]        # 0x2d1820
           6:   68 59 00 00 00          push   0x59
           b:   e9 50 fa ff ff          jmp    0xfffffffffffffa60
    """

    # These class-level intitializers are only for ReadTheDocs
    bits = 32
    bytes = 4
    path = '/path/to/the/file'
    symbols = {}
    got = {}
    plt = {}
    functions = {}
    endian = 'little'
    address = 0x400000
    linker = None

    # Whether to fill gaps in memory with zeroed pages
    _fill_gaps = True


    def __init__(self, path, checksec=True):
        # elftools uses the backing file for all reads and writes
        # in order to permit writing without being able to write to disk,
        # mmap() the file.

        #: :class:`file`: Open handle to the ELF file on disk
        self.file = open(path,'rb')

        #: :class:`mmap.mmap`: Memory-mapped copy of the ELF file on disk
        self.mmap = mmap.mmap(self.file.fileno(), 0, access=mmap.ACCESS_COPY)

        super(ELF,self).__init__(self.mmap)

        #: :class:`str`: Path to the file
        self.path = os.path.abspath(path)

        #: :class:`str`: Architecture of the file (e.g. ``'i386'``, ``'arm'``).
        #:
        #: See: :attr:`.ContextType.arch`
        self.arch = self.get_machine_arch()
        if isinstance(self.arch, (bytes, six.text_type)):
            self.arch = self.arch.lower()

        #: :class:`dotdict` of ``name`` to ``address`` for all symbols in the ELF
        self.symbols = dotdict()

        #: :class:`dotdict` of ``name`` to ``address`` for all Global Offset Table (GOT) entries
        self.got = dotdict()

        #: :class:`dotdict` of ``name`` to ``address`` for all Procedure Linkate Table (PLT) entries
        self.plt = dotdict()

        #: :class:`dotdict` of ``name`` to :class:`.Function` for each function in the ELF
        self.functions = dotdict()

        #: :class:`dict`: Linux kernel configuration, if this is a Linux kernel image
        self.config = {}

        #: :class:`tuple`: Linux kernel version, if this is a Linux kernel image
        self.version = (0,)

        #: :class:`str`: Linux kernel build commit, if this is a Linux kernel image
        self.build = ''

        #: :class:`str`: Endianness of the file (e.g. ``'big'``, ``'little'``)
        self.endian = {
            'ELFDATANONE': 'little',
            'ELFDATA2LSB': 'little',
            'ELFDATA2MSB': 'big'
        }[self['e_ident']['EI_DATA']]

        #: :class:`int`: Bit-ness of the file
        self.bits = self.elfclass

        #: :class:`int`: Pointer width, in bytes
        self.bytes = self.bits // 8

        if self.arch == 'mips':
            mask = lambda a, b: a & b == b
            flags = self.header['e_flags']

            if mask(flags, E_FLAGS.EF_MIPS_ARCH_32) \
            or mask(flags, E_FLAGS.EF_MIPS_ARCH_32R2):
                pass
            elif mask(flags, E_FLAGS.EF_MIPS_ARCH_64) \
            or mask(flags, E_FLAGS.EF_MIPS_ARCH_64R2):
                self.arch = 'mips64'
                self.bits = 64

        self._sections = None
        self._segments = None

        #: IntervalTree which maps all of the loaded memory segments
        self.memory = intervaltree.IntervalTree()
        self._populate_memory()

        # Is this a native binary? Should we be checking QEMU?
        try:
            with context.local(arch=self.arch):
                #: Whether this ELF should be able to run natively
                self.native = context.native
        except AttributeError:
            # The architecture may not be supported in pwntools
            self.native = False

        self._address = 0
        if self.elftype != 'DYN':
            for seg in self.iter_segments_by_type('PT_LOAD'):
                addr = seg.header.p_vaddr
                if addr == 0:
                    continue
                if addr < self._address or self._address == 0:
                    self._address = addr

        self.load_addr = self._address

        # Try to figure out if we have a kernel configuration embedded
        IKCFG_ST=b'IKCFG_ST'

        for start in self.search(IKCFG_ST):
            start += len(IKCFG_ST)
            stop = next(self.search(b'IKCFG_ED'))

            fileobj = BytesIO(self.read(start, stop-start))

            # Python gzip throws an exception if there is non-Gzip data
            # after the Gzip stream.
            #
            # Catch the exception, and just deal with it.
            with gzip.GzipFile(fileobj=fileobj) as gz:
                config = gz.read()

            if config:
                self.config = parse_kconfig(config.decode())

        #: ``True`` if the ELF is a statically linked executable
        self.statically_linked = bool(self.elftype == 'EXEC' and self.load_addr)

        #: ``True`` if the ELF is an executable
        self.executable = bool(self.elftype == 'EXEC')

        for seg in self.iter_segments_by_type('PT_INTERP'):
            self.executable = True

            #: ``True`` if the ELF is statically linked
            self.statically_linked = False

            #: Path to the linker for the ELF
            self.linker = self.read(seg.header.p_vaddr, seg.header.p_memsz)
            self.linker = self.linker.rstrip(b'\x00')

        #: Operating system of the ELF
        self.os = 'linux'

        if self.linker and self.linker.startswith(b'/system/bin/linker'):
            self.os = 'android'

        #: ``True`` if the ELF is a shared library
        self.library = not self.executable and self.elftype == 'DYN'

        try:
            self._populate_symbols()
        except Exception as e:
            log.warn("Could not populate symbols: %s", e)

        try:
            self._populate_got()
        except Exception as e:
            log.warn("Could not populate GOT: %s", e)

        try:
            self._populate_plt()
        except Exception as e:
            log.warn("Could not populate PLT: %s", e)

        self._populate_synthetic_symbols()
        self._populate_functions()
        self._populate_kernel_version()

        if checksec:
            self._describe()

        self._libs = None
        self._maps = None

    @staticmethod
    @LocalContext
    def from_assembly(assembly, *a, **kw):
        """from_assembly(assembly) -> ELF

        Given an assembly listing, return a fully loaded ELF object
        which contains that assembly at its entry point.

        Arguments:

            assembly(str): Assembly language listing
            vma(int): Address of the entry point and the module's base address.

        Example:

            >>> e = ELF.from_assembly('nop; foo: int 0x80', vma = 0x400000)
            >>> e.symbols['foo'] = 0x400001
            >>> e.disasm(e.entry, 1)
            '  400000:       90                      nop'
            >>> e.disasm(e.symbols['foo'], 2)
            '  400001:       cd 80                   int    0x80'
        """
        return ELF(make_elf_from_assembly(assembly, *a, **kw))

    @staticmethod
    @LocalContext
    def from_bytes(bytes, *a, **kw):
        r"""from_bytes(bytes) -> ELF

        Given a sequence of bytes, return a fully loaded ELF object
        which contains those bytes at its entry point.

        Arguments:

            bytes(str): Shellcode byte string
            vma(int): Desired base address for the ELF.

        Example:

            >>> e = ELF.from_bytes(b'\x90\xcd\x80', vma=0xc000)
            >>> print(e.disasm(e.entry, 3))
                c000:       90                      nop
                c001:       cd 80                   int    0x80
        """
        return ELF(make_elf(bytes, extract=False, *a, **kw))

    def process(self, argv=[], *a, **kw):
        """process(argv=[], *a, **kw) -> process

        Execute the binary with :class:`.process`.  Note that ``argv``
        is a list of arguments, and should not include ``argv[0]``.

        Arguments:
            argv(list): List of arguments to the binary
            *args: Extra arguments to :class:`.process`
            **kwargs: Extra arguments to :class:`.process`

        Returns:
            :class:`.process`
        """

        p = process
        if context.os == 'android':
            p = adb.process
        return p([self.path] + argv, *a, **kw)

    def debug(self, argv=[], *a, **kw):
        """debug(argv=[], *a, **kw) -> tube

        Debug the ELF with :func:`.gdb.debug`.

        Arguments:
            argv(list): List of arguments to the binary
            *args: Extra arguments to :func:`.gdb.debug`
            **kwargs: Extra arguments to :func:`.gdb.debug`

        Returns:
            :class:`.tube`: See :func:`.gdb.debug`
        """
        import pwnlib.gdb
        return pwnlib.gdb.debug([self.path] + argv, *a, **kw)

    def _describe(self, *a, **kw):
        log.info_once(
            '%s\n%-10s%s-%s-%s\n%s',
            repr(self.path),
            'Arch:',
            self.arch,
            self.bits,
            self.endian,
            self.checksec(*a, **kw)
        )

    def get_machine_arch(self):
        return {
            'EM_X86_64': 'amd64',
            'EM_386' :'i386',
            'EM_486': 'i386',
            'EM_ARM': 'arm',
            'EM_AARCH64': 'aarch64',
            'EM_MIPS': 'mips',
            'EM_PPC': 'powerpc',
            'EM_PPC64': 'powerpc64',
            'EM_SPARC32PLUS': 'sparc',
            'EM_SPARCV9': 'sparc64',
            'EM_IA_64': 'ia64'
        }.get(self['e_machine'], self['e_machine'])

    @property
    def entry(self):
        """:class:`int`: Address of the entry point for the ELF"""
        return self.address + (self.header.e_entry - self.load_addr)
    entrypoint = entry
    start      = entry

    @property
    def elftype(self):
        """:class:`str`: ELF type (``EXEC``, ``DYN``, etc)"""
        return describe_e_type(self.header.e_type).split()[0]

    def iter_segments(self):
        # Yield and cache all the segments in the file
        if self._segments is None:
            self._segments = [self.get_segment(i) for i in range(self.num_segments())]

        return iter(self._segments)

    @property
    def segments(self):
        """
        :class:`list`: A list of :class:`elftools.elf.segments.Segment` objects
            for the segments in the ELF.
        """
        return list(self.iter_segments())

    def iter_segments_by_type(self, t):
        """
        Yields:
            Segments matching the specified type.
        """
        for seg in self.iter_segments():
            if t == seg.header.p_type or t in str(seg.header.p_type):
                yield seg

    def get_segment_for_address(self, address, size=1):
        """get_segment_for_address(address, size=1) -> Segment

        Given a virtual address described by a ``PT_LOAD`` segment, return the
        first segment which describes the virtual address.  An optional ``size``
        may be provided to ensure the entire range falls into the same segment.

        Arguments:
            address(int): Virtual address to find
            size(int): Number of bytes which must be available after ``address``
                in **both** the file-backed data for the segment, and the memory
                region which is reserved for the data.

        Returns:
            Either returns a :class:`.segments.Segment` object, or ``None``.
        """
        for seg in self.iter_segments_by_type("PT_LOAD"):
            mem_start = seg.header.p_vaddr
            mem_stop  = seg.header.p_memsz + mem_start

            if not (mem_start <= address <= address+size < mem_stop):
                continue

            offset = self.vaddr_to_offset(address)

            file_start = seg.header.p_offset
            file_stop  = seg.header.p_filesz + file_start

            if not (file_start <= offset <= offset+size < file_stop):
                continue

            return seg

        return None

    def iter_sections(self):
        # Yield and cache all the sections in the file
        if self._sections is None:
            self._sections = [self.get_section(i) for i in range(self.num_sections())]

        return iter(self._sections)

    @property
    def sections(self):
        """
        :class:`list`: A list of :class:`elftools.elf.sections.Section` objects
            for the segments in the ELF.
        """
        return list(self.iter_sections())

    @property
    def dwarf(self):
        """DWARF info for the elf"""
        return self.get_dwarf_info()

    @property
    def sym(self):
        """:class:`dotdict`: Alias for :attr:`.ELF.symbols`"""
        return self.symbols

    @property
    def address(self):
        """:class:`int`: Address of the lowest segment loaded in the ELF.

        When updated, the addresses of the following fields are also updated:

        - :attr:`~.ELF.symbols`
        - :attr:`~.ELF.got`
        - :attr:`~.ELF.plt`
        - :attr:`~.ELF.functions`

        However, the following fields are **NOT** updated:

        - :attr:`~.ELF.segments`
        - :attr:`~.ELF.sections`

        Example:

            >>> bash = ELF('/bin/bash')
            >>> read = bash.symbols['read']
            >>> text = bash.get_section_by_name('.text').header.sh_addr
            >>> bash.address += 0x1000
            >>> read + 0x1000 == bash.symbols['read']
            True
            >>> text == bash.get_section_by_name('.text').header.sh_addr
            True
        """
        return self._address

    @address.setter
    def address(self, new):
        delta     = new-self._address
        update    = lambda x: x+delta

        self.symbols = dotdict({k:update(v) for k,v in self.symbols.items()})
        self.plt     = dotdict({k:update(v) for k,v in self.plt.items()})
        self.got     = dotdict({k:update(v) for k,v in self.got.items()})
        for f in self.functions.values():
            f.address += delta

        # Update our view of memory
        memory = intervaltree.IntervalTree()

        for begin, end, data in self.memory:
            memory.addi(update(begin),
                        update(end),
                        data)

        self.memory = memory

        self._address = update(self.address)

    def section(self, name):
        """section(name) -> bytes

        Gets data for the named section

        Arguments:
            name(str): Name of the section

        Returns:
            :class:`str`: String containing the bytes for that section
        """
        return self.get_section_by_name(name).data()

    @property
    def rwx_segments(self):
        """:class:`list`: List of all segments which are writeable and executable.

        See:
            :attr:`.ELF.segments`
        """
        if not self.nx:
            return self.writable_segments

        wx = P_FLAGS.PF_X | P_FLAGS.PF_W
        return [s for s in self.segments if s.header.p_flags & wx == wx]

    @property
    def executable_segments(self):
        """:class:`list`: List of all segments which are executable.

        See:
            :attr:`.ELF.segments`
        """
        if not self.nx:
            return list(self.segments)

        return [s for s in self.segments if s.header.p_flags & P_FLAGS.PF_X]

    @property
    def writable_segments(self):
        """:class:`list`: List of all segments which are writeable.

        See:
            :attr:`.ELF.segments`
        """
        return [s for s in self.segments if s.header.p_flags & P_FLAGS.PF_W]

    @property
    def non_writable_segments(self):
        """:class:`list`: List of all segments which are NOT writeable.

        See:
            :attr:`.ELF.segments`
        """
        return [s for s in self.segments if not s.header.p_flags & P_FLAGS.PF_W]

    @property
    def libs(self):
        """Dictionary of {path: address} for every library loaded for this ELF."""
        if self._libs is None:
            self._populate_libraries()
        return self._libs

    @property
    def maps(self):
        """Dictionary of {name: address} for every mapping in this ELF's address space."""
        if self._maps is None:
            self._populate_libraries()
        return self._maps

    @property
    def libc(self):
        """:class:`.ELF`: If this :class:`.ELF` imports any libraries which contain ``'libc[.-]``,
        and we can determine the appropriate path to it on the local
        system, returns a new :class:`.ELF` object pertaining to that library.

        If not found, the value will be :const:`None`.
        """
        for lib in self.libs:
            if '/libc.' in lib or '/libc-' in lib:
                return ELF(lib)

    def _populate_libraries(self):
        """
        >>> from os.path import exists
        >>> bash = ELF(which('bash'))
        >>> all(map(exists, bash.libs.keys()))
        True
        >>> any(map(lambda x: 'libc' in x, bash.libs.keys()))
        True
        """
        # Patch some shellcode into the ELF and run it.
        maps = self._patch_elf_and_read_maps()

        self._maps = maps
        self._libs = {}

        for lib, address in maps.items():

            # Filter out [stack] and such from the library listings
            if lib.startswith('['):
                continue

            # Any existing files we can just use
            if os.path.exists(lib):
                self._libs[lib] = address

            # Try etc/qemu-binfmt, as per Ubuntu
            if not self.native:
                ld_prefix = qemu.ld_prefix()

                qemu_lib = os.path.join(ld_prefix, lib)
                qemu_lib = os.path.realpath(qemu_lib)

                if os.path.exists(qemu_lib):
                    self._libs[qemu_lib] = address

    def _patch_elf_and_read_maps(self):
        r"""patch_elf_and_read_maps(self) -> dict

        Read ``/proc/self/maps`` as if the ELF were executing.

        This is done by replacing the code at the entry point with shellcode which
        dumps ``/proc/self/maps`` and exits, and **actually executing the binary**.

        Returns:
            A ``dict`` mapping file paths to the lowest address they appear at.
            Does not do any translation for e.g. QEMU emulation, the raw results
            are returned.

            If there is not enough space to inject the shellcode in the segment
            which contains the entry point, returns ``{}``.

        Doctests:

            These tests are just to ensure that our shellcode is correct.

            >>> for arch in CAT_PROC_MAPS_EXIT:
            ...   context.clear()
            ...   with context.local(arch=arch):
            ...     sc = shellcraft.cat("/proc/self/maps")
            ...     sc += shellcraft.exit()
            ...     sc = asm(sc)
            ...     sc = enhex(sc)
            ...     assert sc == CAT_PROC_MAPS_EXIT[arch], (arch, sc)
        """

        # Get our shellcode
        sc = CAT_PROC_MAPS_EXIT.get(self.arch, None)

        if sc is None:
            log.error("Cannot patch /proc/self/maps shellcode into %r binary", self.arch)

        sc = unhex(sc)

        # Ensure there is enough room in the segment where the entry point resides
        # in order to inject our shellcode.
        seg = self.get_segment_for_address(self.entry, len(sc))
        if not seg:
            log.warn_once("Could not inject code to determine memory mapping for %r: Not enough space", self)
            return {}

        # Create our temporary file
        # NOTE: We cannot use "with NamedTemporaryFile() as foo", because we cannot
        # execute the file while the handle is open.
        fd, path = tempfile.mkstemp()

        # Close the file descriptor so that it may be executed
        os.close(fd)

        # Save off a copy of the ELF
        self.save(path)

        # Load a new copy of the ELF at the temporary file location
        old = self.read(self.entry, len(sc))
        try:
            self.write(self.entry, sc)
            self.save(path)
        finally:
            # Restore the original contents
            self.write(self.entry, old)

        # Make the file executable
        os.chmod(path, 0o755)

        # Run a copy of it, get the maps
        try:
            with context.silent:
                io = process(path)
                data = packing._decode(io.recvall(timeout=2))
        except Exception:
            log.warn_once("Injected /proc/self/maps code did not execute correctly")
            return {}

        # Swap in the original ELF name
        data = data.replace(path, self.path)

        # All we care about in the data is the load address of each file-backed mapping,
        # or each kernel-supplied mapping.
        #
        # For quick reference, the data looks like this:
        # 7fcb025f2000-7fcb025f3000 r--p 00025000 fe:01 3025685  /lib/x86_64-linux-gnu/ld-2.23.so
        # 7fcb025f3000-7fcb025f4000 rw-p 00026000 fe:01 3025685  /lib/x86_64-linux-gnu/ld-2.23.so
        # 7fcb025f4000-7fcb025f5000 rw-p 00000000 00:00 0
        # 7ffe39cd4000-7ffe39cf6000 rw-p 00000000 00:00 0        [stack]
        # 7ffe39d05000-7ffe39d07000 r--p 00000000 00:00 0        [vvar]
        result = {}
        for line in data.splitlines():
            if '/' in line:
                index = line.index('/')
            elif '[' in line:
                index = line.index('[')
            else:
                continue

            address, _ = line.split('-', 1)

            address = int(address, 0x10)
            name = line[index:]

            result.setdefault(name, address)

        # Remove the temporary file, best-effort
        os.unlink(path)

        return result

    def _populate_functions(self):
        """Builds a dict of 'functions' (i.e. symbols of type 'STT_FUNC')
        by function name that map to a tuple consisting of the func address and size
        in bytes.
        """
        for sec in self.sections:
            if not isinstance(sec, SymbolTableSection):
                continue

            for sym in _iter_symbols(sec):
                # Avoid duplicates
                if sym.name in self.functions:
                    continue
                if sym.entry.st_info['type'] == 'STT_FUNC' and sym.entry.st_size != 0:
                    name = sym.name
                    if name not in self.symbols:
                        continue
                    addr = self.symbols[name]
                    size = sym.entry.st_size
                    self.functions[name] = Function(name, addr, size, self)

    def _populate_symbols(self):
        """
        >>> bash = ELF(which('bash'))
        >>> bash.symbols['_start'] == bash.entry
        True
        """

        # Populate all of the "normal" symbols from the symbol tables
        for section in self.sections:
            if not isinstance(section, SymbolTableSection):
                continue

            for symbol in _iter_symbols(section):
                value = symbol.entry.st_value
                if not value:
                    continue
                self.symbols[symbol.name] = value

    def _populate_synthetic_symbols(self):
        """Adds symbols from the GOT and PLT to the symbols dictionary.

        Does not overwrite any existing symbols, and prefers PLT symbols.

        Synthetic plt.xxx and got.xxx symbols are added for each PLT and
        GOT entry, respectively.

        Example:bash.

            >>> bash = ELF(which('bash'))
            >>> bash.symbols.wcscmp == bash.plt.wcscmp
            True
            >>> bash.symbols.wcscmp == bash.symbols.plt.wcscmp
            True
            >>> bash.symbols.stdin  == bash.got.stdin
            True
            >>> bash.symbols.stdin  == bash.symbols.got.stdin
            True
        """
        for symbol, address in self.plt.items():
            self.symbols.setdefault(symbol, address)
            self.symbols['plt.' + symbol] = address

        for symbol, address in self.got.items():
            self.symbols.setdefault(symbol, address)
            self.symbols['got.' + symbol] = address

    def _populate_got(self):
        """Loads the symbols for all relocations"""
        # Statically linked implies no relocations, since there is no linker
        # Could always be self-relocating like Android's linker *shrug*
        if self.statically_linked:
            return

        for section in self.sections:
            # We are only interested in relocations
            if not isinstance(section, RelocationSection):
                continue

            # Only get relocations which link to another section (for symbols)
            if section.header.sh_link == SHN_INDICES.SHN_UNDEF:
                continue

            symbols = self.get_section(section.header.sh_link)

            for rel in section.iter_relocations():
                sym_idx  = rel.entry.r_info_sym

                if not sym_idx:
                    continue

                symbol = symbols.get_symbol(sym_idx)

                if symbol and symbol.name:
                    self.got[symbol.name] = rel.entry.r_offset

        if self.arch == 'mips':
            try:
                self._populate_mips_got()
            except Exception as e:
                log.warn("Could not populate MIPS GOT: %s", e)

        if not self.got:
            log.warn("Did not find any GOT entries")

    def _populate_mips_got(self):
        self._mips_got = {}
        strings = self.get_section(self.header.e_shstrndx)

        ELF_MIPS_GNU_GOT1_MASK = 0x80000000

        if self.bits == 64:
            ELF_MIPS_GNU_GOT1_MASK <<= 32

        # Beginning of the GOT
        got = self.dynamic_value_by_tag('DT_PLTGOT') or 0

        # Find the beginning of the GOT pointers
        got1_mask = (self.unpack(got) & ELF_MIPS_GNU_GOT1_MASK)
        i = 2 if got1_mask else 1
        self._mips_skip = i

        # We don't care about local GOT entries, skip them
        local_gotno = self.dynamic_value_by_tag('DT_MIPS_LOCAL_GOTNO')
        got += local_gotno * context.bytes

        # Iterate over the dynamic symbol table
        dynsym = self.get_section_by_name('.dynsym')
        symbol_iter = _iter_symbols(dynsym)

        # 'gotsym' is the index of the first GOT symbol
        gotsym = self.dynamic_value_by_tag('DT_MIPS_GOTSYM')
        for i in range(gotsym):
            next(symbol_iter)

        # 'symtabno' is the total number of symbols
        symtabno = self.dynamic_value_by_tag('DT_MIPS_SYMTABNO')

        for i in range(symtabno - gotsym):
            symbol = next(symbol_iter)
            self._mips_got[i + gotsym] = got
            self.got[symbol.name] = got
            got += self.bytes

    def _populate_plt(self):
        """Loads the PLT symbols

        >>> path = pwnlib.data.elf.path
        >>> for test in glob(os.path.join(path, 'test-*')):
        ...     test = ELF(test)
        ...     assert '__stack_chk_fail' in test.got, test
        ...     if test.arch != 'ppc':
        ...         assert '__stack_chk_fail' in test.plt, test
        """
        if self.statically_linked:
            log.debug("%r is statically linked, skipping GOT/PLT symbols" % self.path)
            return

        if not self.got:
            log.debug("%r doesn't have any GOT symbols, skipping PLT" % self.path)
            return

        # This element holds an address associated with the procedure linkage table
        # and/or the global offset table.
        #
        # Zach's note: This corresponds to the ".got.plt" section, in a PIE non-RELRO binary.
        #              This corresponds to the ".got" section, in a PIE full-RELRO binary.
        #              In particular, this is where EBX points when it points into the GOT.
        dt_pltgot = self.dynamic_value_by_tag('DT_PLTGOT') or 0

        # There are three PLTs we may need to search
        plt = self.get_section_by_name('.plt')          # <-- Functions only
        plt_got = self.get_section_by_name('.plt.got')  # <-- Functions used as data
        plt_sec = self.get_section_by_name('.plt.sec')
        plt_mips = self.get_section_by_name('.MIPS.stubs')

        # Invert the GOT symbols we already have, so we can look up by address
        inv_symbols = {v:k for k,v in self.got.items()}
        inv_symbols.update({v:k for k,v in self.symbols.items()})

        with context.local(arch=self.arch, bits=self.bits, endian=self.endian):
            for section in (plt, plt_got, plt_sec, plt_mips):
                if not section:
                    continue

                res = emulate_plt_instructions(self,
                                                dt_pltgot,
                                                section.header.sh_addr,
                                                section.data(),
                                                inv_symbols)

                for address, target in sorted(res.items()):
                    self.plt[inv_symbols[target]] = address

        # for a,n in sorted({v:k for k,v in self.plt.items()}.items()):
            # log.debug('PLT %#x %s', a, n)

    def _populate_kernel_version(self):
        if 'linux_banner' not in self.symbols:
            return

        banner = self.string(self.symbols.linux_banner)
        
        # convert banner into a utf-8 string since re.search does not accept bytes anymore
        banner = banner.decode('utf-8')
        
        # 'Linux version 3.18.31-gd0846ecc
        regex = r'Linux version (\S+)'
        match = re.search(regex, banner)

        if match:
            version = match.group(1)

            if '-' in version:
                version, self.build = version.split('-', 1)

            self.version = list(map(int, version.rstrip('+').split('.')))

        self.config['version'] = self.version

    @property
    def libc_start_main_return(self):
        """
            Try to find the return address from main into __libc_start_main.
            The heuristic to find the call to the function pointer of main is
            to list all calls inside __libc_start_main, find the call to exit
            after the call to main and select the previous call.
        """
        if '__libc_start_main' not in self.functions:
            return 0

        if 'exit' not in self.symbols:
            return 0

        # If there's no delay slot, execution continues on the next instruction after a call.
        call_return_offset = 1
        if self.arch in ['arm', 'thumb']:
            call_instructions = set(['blx', 'bl'])
        elif self.arch == 'aarch64':
            call_instructions = set(['blr', 'bl'])
        elif self.arch in ['mips', 'mips64']:
            call_instructions = set(['bal', 'jalr'])
            # Account for the delay slot.
            call_return_offset = 2
        elif self.arch in ['i386', 'amd64', 'ia64']:
            call_instructions = set(['call'])
        else:
            log.error('Unsupported architecture %s in ELF.libc_start_main_return', self.arch)
            return 0
        
        code = self.disasm(self.symbols['__libc_start_main'], self.functions['__libc_start_main'].size)
        exit_addr = hex(self.symbols['exit'])
        lines = code.split('\n')
        calls = [(index, line) for index, line in enumerate(lines) if set(line.split()) & call_instructions]
        exit_calls = [index for index, line in enumerate(calls) if exit_addr in line[1]]
        if len(exit_calls) != 1:
            return 0

        call_to_main = calls[exit_calls[0] - 1]
        return_from_main = lines[call_to_main[0] + call_return_offset].lstrip()
        return_from_main = int(return_from_main[ : return_from_main.index(':') ], 16)
        return return_from_main

    def search(self, needle, writable = False, executable = False):
        """search(needle, writable = False, executable = False) -> generator

        Search the ELF's virtual address space for the specified string.

        Notes:
            Does not search empty space between segments, or uninitialized
            data.  This will only return data that actually exists in the
            ELF file.  Searching for a long string of NULL bytes probably
            won't work.

        Arguments:
            needle(str): String to search for.
            writable(bool): Search only writable sections.
            executable(bool): Search only executable sections.

        Yields:
            An iterator for each virtual address that matches.

        Examples:

            An ELF header starts with the bytes ``\\x7fELF``, so we
            sould be able to find it easily.

            >>> bash = ELF('/bin/bash')
            >>> bash.address + 1 == next(bash.search(b'ELF'))
            True

            We can also search for string the binary.

            >>> len(list(bash.search(b'GNU bash'))) > 0
            True

            It is also possible to search for instructions in executable sections.

            >>> binary = ELF.from_assembly('nop; mov eax, 0; jmp esp; ret')
            >>> jmp_addr = next(binary.search(asm('jmp esp'), executable = True))
            >>> binary.read(jmp_addr, 2) == asm('jmp esp')
            True
        """
        load_address_fixup = (self.address - self.load_addr)

        if writable:
            segments = self.writable_segments
        elif executable:
            segments = self.executable_segments
        else:
            segments = self.segments

        for seg in segments:
            addr   = seg.header.p_vaddr
            memsz  = seg.header.p_memsz
            zeroed = memsz - seg.header.p_filesz
            offset = seg.header.p_offset
            data   = self.mmap[offset:offset+memsz]
            data   += b'\x00' * zeroed
            offset = 0
            while True:
                offset = data.find(needle, offset)
                if offset == -1:
                    break
                yield (addr + offset + load_address_fixup)
                offset += 1

    def offset_to_vaddr(self, offset):
        """offset_to_vaddr(offset) -> int

        Translates the specified offset to a virtual address.

        Arguments:
            offset(int): Offset to translate

        Returns:
            `int`: Virtual address which corresponds to the file offset, or
            :const:`None`.

        Examples:

            This example shows that regardless of changes to the virtual
            address layout by modifying :attr:`.ELF.address`, the offset
            for any given address doesn't change.

            >>> bash = ELF('/bin/bash')
            >>> bash.address == bash.offset_to_vaddr(0)
            True
            >>> bash.address += 0x123456
            >>> bash.address == bash.offset_to_vaddr(0)
            True
        """
        load_address_fixup = (self.address - self.load_addr)

        for segment in self.segments:
            begin = segment.header.p_offset
            size  = segment.header.p_filesz
            end   = begin + size
            if begin <= offset and offset <= end:
                delta = offset - begin
                return segment.header.p_vaddr + delta + load_address_fixup
        return None

    def _populate_memory(self):
        load_segments = list(filter(lambda s: s.header.p_type == 'PT_LOAD', self.iter_segments()))

        # Map all of the segments
        for i, segment in enumerate(load_segments):
            start = segment.header.p_vaddr
            stop_data = start + segment.header.p_filesz
            stop_mem  = start + segment.header.p_memsz

            # Chop any existing segments which cover the range described by
            # [vaddr, vaddr+filesz].
            #
            # This has the effect of removing any issues we may encounter
            # with "overlapping" segments, by giving precedence to whichever
            # DT_LOAD segment is **last** to load data into the region.
            self.memory.chop(start, stop_data)

            # Fill the start of the segment's first page
            page_start = align_down(0x1000, start)
            if page_start < start and not self.memory[page_start]:
                self.memory.addi(page_start, start, None)

            # Add the new segment
            if start != stop_data:
                self.memory.addi(start, stop_data, segment)

            if stop_data != stop_mem:
                self.memory.addi(stop_data, stop_mem, b'\x00')

            page_end = align(0x1000, stop_mem)

            # Check for holes which we can fill
            if self._fill_gaps and i+1 < len(load_segments):
                next_start = load_segments[i+1].header.p_vaddr
                page_next = align_down(0x1000, next_start)

                if stop_mem < next_start:
                    if page_end < page_next:
                        if stop_mem < page_end:
                            self.memory.addi(stop_mem, page_end, None)
                        if page_next < next_start:
                            self.memory.addi(page_next, next_start, None)
                    else:
                        self.memory.addi(stop_mem, next_start, None)
            else:
                if stop_mem < page_end:
                    self.memory.addi(stop_mem, page_end, None)

    def vaddr_to_offset(self, address):
        """vaddr_to_offset(address) -> int

        Translates the specified virtual address to a file offset

        Arguments:
            address(int): Virtual address to translate

        Returns:
            int: Offset within the ELF file which corresponds to the address,
            or :const:`None`.

        Examples:
            >>> bash = ELF(which('bash'))
            >>> bash.vaddr_to_offset(bash.address)
            0
            >>> bash.address += 0x123456
            >>> bash.vaddr_to_offset(bash.address)
            0
            >>> bash.vaddr_to_offset(0) is None
            True
        """

        for interval in self.memory[address]:
            segment = interval.data

            # Convert the address back to how it was when the segment was loaded
            address = (address - self.address) + self.load_addr

            # Figure out the offset into the segment
            offset = address - segment.header.p_vaddr

            # Add the segment-base offset to the offset-within-the-segment
            return segment.header.p_offset + offset

    def read(self, address, count):
        r"""read(address, count) -> bytes

        Read data from the specified virtual address

        Arguments:
            address(int): Virtual address to read
            count(int): Number of bytes to read

        Returns:
            A :class:`str` object, or :const:`None`.

        Examples:
            The simplest example is just to read the ELF header.

            >>> bash = ELF(which('bash'))
            >>> bash.read(bash.address, 4)
            b'\x7fELF'

            ELF segments do not have to contain all of the data on-disk
            that gets loaded into memory.

            First, let's create an ELF file has some code in two sections.

            >>> assembly = '''
            ... .section .A,"awx"
            ... .global A
            ... A: nop
            ... .section .B,"awx"
            ... .global B
            ... B: int3
            ... '''
            >>> e = ELF.from_assembly(assembly, vma=False)

            By default, these come right after eachother in memory.

            >>> e.read(e.symbols.A, 2)
            b'\x90\xcc'
            >>> e.symbols.B - e.symbols.A
            1

            Let's move the sections so that B is a little bit further away.

            >>> objcopy = pwnlib.asm._objcopy()
            >>> objcopy += [
            ...     '--change-section-vma', '.B+5',
            ...     '--change-section-lma', '.B+5',
            ...     e.path
            ... ]
            >>> subprocess.check_call(objcopy)
            0

            Now let's re-load the ELF, and check again

            >>> e = ELF(e.path)
            >>> e.symbols.B - e.symbols.A
            6
            >>> e.read(e.symbols.A, 2)
            b'\x90\x00'
            >>> e.read(e.symbols.A, 7)
            b'\x90\x00\x00\x00\x00\x00\xcc'
            >>> e.read(e.symbols.A, 10)
            b'\x90\x00\x00\x00\x00\x00\xcc\x00\x00\x00'

            Everything is relative to the user-selected base address, so moving
            things around keeps everything working.

            >>> e.address += 0x1000
            >>> e.read(e.symbols.A, 10)
            b'\x90\x00\x00\x00\x00\x00\xcc\x00\x00\x00'
        """
        retval = []

        if count == 0:
            return b''

        start = address
        stop = address + count

        overlap = self.memory.overlap(start, stop)

        # Create a new view of memory, for just what we need
        memory = intervaltree.IntervalTree(overlap)
        memory.chop(-1<<64, start)
        memory.chop(stop, 1<<64)

        if memory.begin() != start:
            log.error("Address %#x is not contained in %s" % (start, self))

        if memory.end() != stop:
            log.error("Address %#x is not contained in %s" % (stop, self))

        # We have a view of memory which lets us get everything we need
        for begin, end, data in sorted(memory):
            length = end-begin

            if data in (None, b'\x00'):
                retval.append(b'\x00' * length)
                continue

            # Offset within VMA range
            begin -= self.address

            # Adjust to original VMA range
            begin += self.load_addr

            # Adjust to offset within segment VMA
            offset = begin - data.header.p_vaddr

            # Adjust in-segment offset to in-file offset
            offset += data.header.p_offset

            retval.append(self.mmap[offset:offset+length])

        return b''.join(retval)

    def write(self, address, data):
        """Writes data to the specified virtual address

        Arguments:
            address(int): Virtual address to write
            data(str): Bytes to write

        Note:
            This routine does not check the bounds on the write to ensure
            that it stays in the same segment.

        Examples:
          >>> bash = ELF(which('bash'))
          >>> bash.read(bash.address+1, 3)
          b'ELF'
          >>> bash.write(bash.address, b"HELO")
          >>> bash.read(bash.address, 4)
          b'HELO'
        """
        offset = self.vaddr_to_offset(address)

        if offset is not None:
            length = len(data)
            self.mmap[offset:offset+length] = data

        return None

    def save(self, path=None):
        """Save the ELF to a file

        >>> bash = ELF(which('bash'))
        >>> bash.save('/tmp/bash_copy')
        >>> copy = open('/tmp/bash_copy', 'rb')
        >>> bash = open(which('bash'), 'rb')
        >>> bash.read() == copy.read()
        True
        """
        if path is None:
            path = self.path
        misc.write(path, self.data)

    def get_data(self):
        """get_data() -> bytes

        Retrieve the raw data from the ELF file.

        >>> bash = ELF(which('bash'))
        >>> fd   = open(which('bash'), 'rb')
        >>> bash.get_data() == fd.read()
        True
        """
        return self.mmap[:]

    @property
    def data(self):
        """:class:`str`: Raw data of the ELF file.

        See:
            :meth:`get_data`
        """
        return self.mmap[:]

    def disasm(self, address, n_bytes):
        """disasm(address, n_bytes) -> str

        Returns a string of disassembled instructions at
        the specified virtual memory address"""
        arch = self.arch
        if self.arch == 'arm' and address & 1:
            arch = 'thumb'
            address -= 1

        return disasm(self.read(address, n_bytes), vma=address, arch=arch, endian=self.endian)

    def asm(self, address, assembly):
        """asm(address, assembly)

        Assembles the specified instructions and inserts them
        into the ELF at the specified address.

        This modifies the ELF in-place.
        The resulting binary can be saved with :meth:`.ELF.save`
        """
        binary = asm(assembly, vma=address)
        self.write(address, binary)

    def bss(self, offset=0):
        """bss(offset=0) -> int

        Returns:
            Address of the ``.bss`` section, plus the specified offset.
        """
        orig_bss = self.get_section_by_name('.bss').header.sh_addr
        curr_bss = orig_bss - self.load_addr + self.address
        return curr_bss + offset

    def __repr__(self):
        return "%s(%r)" % (self.__class__.__name__, self.path)

    def dynamic_by_tag(self, tag):
        """dynamic_by_tag(tag) -> tag

        Arguments:
            tag(str): Named ``DT_XXX`` tag (e.g. ``'DT_STRTAB'``).

        Returns:
            :class:`elftools.elf.dynamic.DynamicTag`
        """
        dt      = None
        dynamic = self.get_section_by_name('.dynamic')

        if not dynamic:
            return None

        try:
            dt = next(t for t in dynamic.iter_tags() if tag == t.entry.d_tag)
        except StopIteration:
            pass

        return dt

    def dynamic_value_by_tag(self, tag):
        """dynamic_value_by_tag(tag) -> int

        Retrieve the value from a dynamic tag a la ``DT_XXX``.

        If the tag is missing, returns ``None``.
        """
        tag = self.dynamic_by_tag(tag)

        if tag:
            return tag.entry.d_val

    def dynamic_string(self, offset):
        """dynamic_string(offset) -> bytes

        Fetches an enumerated string from the ``DT_STRTAB`` table.

        Arguments:
            offset(int): String index

        Returns:
            :class:`str`: String from the table as raw bytes.
        """
        dt_strtab = self.dynamic_by_tag('DT_STRTAB')

        if not dt_strtab:
            return None

        address   = dt_strtab.entry.d_ptr + offset
        string    = b''
        while b'\x00' not in string:
            string  += self.read(address, 1)
            address += 1
        return string.rstrip(b'\x00')



    @property
    def relro(self):
        """:class:`bool`: Whether the current binary uses RELRO protections.

        This requires both presence of the dynamic tag ``DT_BIND_NOW``, and
        a ``GNU_RELRO`` program header.

        The `ELF Specification`_ describes how the linker should resolve
        symbols immediately, as soon as a binary is loaded.  This can be
        emulated with the ``LD_BIND_NOW=1`` environment variable.

            ``DT_BIND_NOW``

            If present in a shared object or executable, this entry instructs
            the dynamic linker to process all relocations for the object
            containing this entry before transferring control to the program.
            The presence of this entry takes precedence over a directive to use
            lazy binding for this object when specified through the environment
            or via ``dlopen(BA_LIB)``.

            (`page 81`_)

        Separately, an extension to the GNU linker allows a binary to specify
        a PT_GNU_RELRO_ program header, which describes the *region of memory
        which is to be made read-only after relocations are complete.*

        Finally, a new-ish extension which doesn't seem to have a canonical
        source of documentation is DF_BIND_NOW_, which has supposedly superceded
        ``DT_BIND_NOW``.

            ``DF_BIND_NOW``

            If set in a shared object or executable, this flag instructs the
            dynamic linker to process all relocations for the object containing
            this entry before transferring control to the program. The presence
            of this entry takes precedence over a directive to use lazy binding
            for this object when specified through the environment or via
            ``dlopen(BA_LIB)``.

        .. _ELF Specification: https://refspecs.linuxbase.org/elf/elf.pdf
        .. _page 81: https://refspecs.linuxbase.org/elf/elf.pdf#page=81
        .. _DT_BIND_NOW: https://refspecs.linuxbase.org/elf/elf.pdf#page=81
        .. _PT_GNU_RELRO: https://refspecs.linuxbase.org/LSB_3.1.1/LSB-Core-generic/LSB-Core-generic.html#PROGHEADER
        .. _DF_BIND_NOW: http://refspecs.linuxbase.org/elf/gabi4+/ch5.dynamic.html#df_bind_now

        >>> path = pwnlib.data.elf.relro.path
        >>> for test in glob(os.path.join(path, 'test-*')):
        ...     e = ELF(test)
        ...     expected = os.path.basename(test).split('-')[2]
        ...     actual = str(e.relro).lower()
        ...     assert actual == expected
        """
        if not any('GNU_RELRO' in str(s.header.p_type) for s in self.segments):
            return None

        if self.dynamic_by_tag('DT_BIND_NOW'):
            return "Full"

        flags = self.dynamic_value_by_tag('DT_FLAGS')
        if flags and flags & constants.DF_BIND_NOW:
            return "Full"

        flags_1 = self.dynamic_value_by_tag('DT_FLAGS_1')
        if flags_1 and flags_1 & constants.DF_1_NOW:
            return "Full"

        return "Partial"

    @property
    def nx(self):
        """:class:`bool`: Whether the current binary uses NX protections.

        Specifically, we are checking for ``READ_IMPLIES_EXEC`` being set
        by the kernel, as a result of honoring ``PT_GNU_STACK`` in the kernel.

        The **Linux kernel** directly honors ``PT_GNU_STACK`` to `mark the
        stack as executable.`__

        .. __: https://github.com/torvalds/linux/blob/v4.9/fs/binfmt_elf.c#L784-L789

        .. code-block:: c

            case PT_GNU_STACK:
                if (elf_ppnt->p_flags & PF_X)
                    executable_stack = EXSTACK_ENABLE_X;
                else
                    executable_stack = EXSTACK_DISABLE_X;
                break;

        Additionally, it then sets ``read_implies_exec``, so that `all readable pages
        are executable`__.

        .. __: https://github.com/torvalds/linux/blob/v4.9/fs/binfmt_elf.c#L849-L850

        .. code-block:: c

            if (elf_read_implies_exec(loc->elf_ex, executable_stack))
                current->personality |= READ_IMPLIES_EXEC;
        """
        if not self.executable:
            return True

        for seg in self.iter_segments_by_type('GNU_STACK'):
            return not bool(seg.header.p_flags & P_FLAGS.PF_X)

        # If you NULL out the PT_GNU_STACK section via ELF.disable_nx(),
        # everything is executable.
        return False

    @property
    def execstack(self):
        """:class:`bool`: Whether the current binary uses an executable stack.

        This is based on the presence of a program header PT_GNU_STACK_
        being present, and its setting.

            ``PT_GNU_STACK``

            The p_flags member specifies the permissions on the segment
            containing the stack and is used to indicate whether the stack
            should be executable. The absense of this header indicates
            that the stack will be executable.

        In particular, if the header is missing the stack is executable.
        If the header is present, it may **explicitly** mark that the stack is
        executable.

        This is only somewhat accurate.  When using the GNU Linker, it usees
        DEFAULT_STACK_PERMS_ to decide whether a lack of ``PT_GNU_STACK``
        should mark the stack as executable:

        .. code-block:: c

            /* On most platforms presume that PT_GNU_STACK is absent and the stack is
             * executable.  Other platforms default to a nonexecutable stack and don't
             * need PT_GNU_STACK to do so.  */
            uint_fast16_t stack_flags = DEFAULT_STACK_PERMS;

        By searching the source for ``DEFAULT_STACK_PERMS``, we can see which
        architectures have which settings.

        ::

            $ git grep '#define DEFAULT_STACK_PERMS' | grep -v PF_X
            sysdeps/aarch64/stackinfo.h:31:#define DEFAULT_STACK_PERMS (PF_R|PF_W)
            sysdeps/nios2/stackinfo.h:31:#define DEFAULT_STACK_PERMS (PF_R|PF_W)
            sysdeps/tile/stackinfo.h:31:#define DEFAULT_STACK_PERMS (PF_R|PF_W)

        .. _PT_GNU_STACK: https://refspecs.linuxbase.org/LSB_3.0.0/LSB-PDA/LSB-PDA/progheader.html
        .. _DEFAULT_STACK_PERMS: https://github.com/bminor/glibc/blob/glibc-2.25/elf/dl-load.c#L1036-L1038
        """
        # Dynamic objects do not have the ability to change the executable state of the stack.
        if not self.executable:
            return False

        # If NX is completely off for the process, the stack is executable.
        if not self.nx:
            return True

        # If the ``PT_GNU_STACK`` program header is missing, then use the
        # default rules.  Only AArch64 gets a non-executable stack by default.
        for _ in self.iter_segments_by_type('GNU_STACK'):
            break
        else:
            return self.arch != 'aarch64'

        return False

    @property
    def canary(self):
        """:class:`bool`: Whether the current binary uses stack canaries."""

        # Sometimes there is no function for __stack_chk_fail,
        # but there is an entry in the GOT
        return '__stack_chk_fail' in (set(self.symbols) | set(self.got))

    @property
    def packed(self):
        """:class:`bool`: Whether the current binary is packed with UPX."""
        return b'UPX!' in self.get_data()

    @property
    def pie(self):
        """:class:`bool`: Whether the current binary is position-independent."""
        return self.elftype == 'DYN'
    aslr=pie

    @property
    def rpath(self):
        """:class:`bool`: Whether the current binary has an ``RPATH``."""
        dt_rpath = self.dynamic_by_tag('DT_RPATH')

        if not dt_rpath:
            return None

        return self.dynamic_string(dt_rpath.entry.d_ptr)

    @property
    def runpath(self):
        """:class:`bool`: Whether the current binary has a ``RUNPATH``."""
        dt_runpath = self.dynamic_by_tag('DT_RUNPATH')

        if not dt_runpath:
            return None

        return self.dynamic_string(dt_runpath.entry.d_ptr)

    def checksec(self, banner=True, color=True):
        """checksec(banner=True, color=True)

        Prints out information in the binary, similar to ``checksec.sh``.

        Arguments:
            banner(bool): Whether to print the path to the ELF binary.
            color(bool): Whether to use colored output.
        """
        red    = text.red if color else str
        green  = text.green if color else str
        yellow = text.yellow if color else str

        res = []

        # Kernel version?
        if self.version and self.version != (0,):
            res.append('Version:'.ljust(10) + '.'.join(map(str, self.version)))
        if self.build:
            res.append('Build:'.ljust(10) + self.build)

        res.extend([
            "RELRO:".ljust(10) + {
                'Full':    green("Full RELRO"),
                'Partial': yellow("Partial RELRO"),
                None:      red("No RELRO")
            }[self.relro],
            "Stack:".ljust(10) + {
                True:  green("Canary found"),
                False: red("No canary found")
            }[self.canary],
            "NX:".ljust(10) + {
                True:  green("NX enabled"),
                False: red("NX disabled"),
            }[self.nx],
            "PIE:".ljust(10) + {
                True: green("PIE enabled"),
                False: red("No PIE (%#x)" % self.address)
            }[self.pie],
        ])

        # Execstack may be a thing, even with NX enabled, because of glibc
        if self.execstack and self.nx:
            res.append("Stack:".ljust(10) + red("Executable"))

        # Are there any RWX areas in the binary?
        #
        # This will occur if NX is disabled and *any* area is
        # RW, or can expressly occur.
        if self.rwx_segments or (not self.nx and self.writable_segments):
            res += [ "RWX:".ljust(10) + red("Has RWX segments") ]

        if self.rpath:
            res += [ "RPATH:".ljust(10) + red(repr(self.rpath)) ]

        if self.runpath:
            res += [ "RUNPATH:".ljust(10) + red(repr(self.runpath)) ]

        if self.packed:
            res.append('Packer:'.ljust(10) + red("Packed with UPX"))

        if self.fortify:
            res.append("FORTIFY:".ljust(10) + green("Enabled"))

        if self.asan:
            res.append("ASAN:".ljust(10) + green("Enabled"))

        if self.msan:
            res.append("MSAN:".ljust(10) + green("Enabled"))

        if self.ubsan:
            res.append("UBSAN:".ljust(10) + green("Enabled"))

        # Check for Linux configuration, it must contain more than
        # just the version.
        if len(self.config) > 1:
            config_opts = collections.defaultdict(list)
            for checker in kernel_configuration:
                result, message = checker(self.config)

                if not result:
                    config_opts[checker.title].append((checker.name, message))


            for title, values in config_opts.items():
                res.append(title + ':')
                for name, message in sorted(values):
                    line = '{} = {}'.format(name, red(str(self.config.get(name, None))))
                    if message:
                        line += ' ({})'.format(message)
                    res.append('    ' + line)

            # res.extend(sorted(config_opts))

        return '\n'.join(res)

    @property
    def buildid(self):
        """:class:`str`: GNU Build ID embedded into the binary"""
        section = self.get_section_by_name('.note.gnu.build-id')
        if section:
            return section.data()[16:]
        return None

    @property
    def fortify(self):
        """:class:`bool`: Whether the current binary was built with
        Fortify Source (``-DFORTIFY``)."""
        if any(s.endswith('_chk') for s in self.plt):
            return True
        return False

    @property
    def asan(self):
        """:class:`bool`: Whether the current binary was built with
        Address Sanitizer (``ASAN``)."""
        return any(s.startswith('__asan_') for s in self.symbols)

    @property
    def msan(self):
        """:class:`bool`: Whether the current binary was built with
        Memory Sanitizer (``MSAN``)."""
        return any(s.startswith('__msan_') for s in self.symbols)

    @property
    def ubsan(self):
        """:class:`bool`: Whether the current binary was built with
        Undefined Behavior Sanitizer (``UBSAN``)."""
        return any(s.startswith('__ubsan_') for s in self.symbols)

    def _update_args(self, kw):
        kw.setdefault('arch', self.arch)
        kw.setdefault('bits', self.bits)
        kw.setdefault('endian', self.endian)

    def p64(self,  address, data, *a, **kw):
        """Writes a 64-bit integer ``data`` to the specified ``address``"""
        self._update_args(kw)
        return self.write(address, packing.p64(data, *a, **kw))

    def p32(self,  address, data, *a, **kw):
        """Writes a 32-bit integer ``data`` to the specified ``address``"""
        self._update_args(kw)
        return self.write(address, packing.p32(data, *a, **kw))

    def p16(self,  address, data, *a, **kw):
        """Writes a 16-bit integer ``data`` to the specified ``address``"""
        self._update_args(kw)
        return self.write(address, packing.p16(data, *a, **kw))

    def p8(self,   address, data, *a, **kw):
        """Writes a 8-bit integer ``data`` to the specified ``address``"""
        self._update_args(kw)
        return self.write(address, packing.p8(data, *a, **kw))

    def pack(self, address, data, *a, **kw):
        """Writes a packed integer ``data`` to the specified ``address``"""
        self._update_args(kw)
        return self.write(address, packing.pack(data, *a, **kw))

    def u64(self,    address, *a, **kw):
        """Unpacks an integer from the specified ``address``."""
        self._update_args(kw)
        return packing.u64(self.read(address, 8), *a, **kw)

    def u32(self,    address, *a, **kw):
        """Unpacks an integer from the specified ``address``."""
        self._update_args(kw)
        return packing.u32(self.read(address, 4), *a, **kw)

    def u16(self,    address, *a, **kw):
        """Unpacks an integer from the specified ``address``."""
        self._update_args(kw)
        return packing.u16(self.read(address, 2), *a, **kw)

    def u8(self,     address, *a, **kw):
        """Unpacks an integer from the specified ``address``."""
        self._update_args(kw)
        return packing.u8(self.read(address, 1), *a, **kw)

    def unpack(self, address, *a, **kw):
        """Unpacks an integer from the specified ``address``."""
        self._update_args(kw)
        return packing.unpack(self.read(address, self.bytes), *a, **kw)

    def string(self, address):
        """string(address) -> str

        Reads a null-terminated string from the specified ``address``

        Returns:
            A ``str`` with the string contents (NUL terminator is omitted),
            or an empty string if no NUL terminator could be found.
        """
        data = b''
        while True:
            read_size = 0x1000
            partial_page = address & 0xfff

            if partial_page:
                read_size -= partial_page

            c = self.read(address, read_size)

            if not c:
                return b''

            data += c

            if b'\x00' in c:
                return data[:data.index(b'\x00')]

            address += len(c)

    def flat(self, address, *a, **kw):
        """Writes a full array of values to the specified address.

        See: :func:`.packing.flat`
        """
        return self.write(address, packing.flat(*a,**kw))

    def fit(self, address, *a, **kw):
        """Writes fitted data into the specified address.

        See: :func:`.packing.fit`
        """
        return self.write(address, packing.fit(*a, **kw))

    def parse_kconfig(self, data):
        self.config.update(parse_kconfig(data))

    def disable_nx(self):
        """Disables NX for the ELF.

        Zeroes out the ``PT_GNU_STACK`` program header ``p_type`` field.
        """
        PT_GNU_STACK = packing.p32(ENUM_P_TYPE['PT_GNU_STACK'])

        if not self.executable:
            log.error("Can only make stack executable with executables")

        for i, segment in enumerate(self.iter_segments()):
            if not segment.header.p_type:
                continue
            if 'GNU_STACK' not in segment.header.p_type:
                continue

            phoff = self.header.e_phoff
            phentsize = self.header.e_phentsize
            offset = phoff + phentsize * i

            if self.mmap[offset:offset+4] == PT_GNU_STACK:
                self.mmap[offset:offset+4] = b'\x00' * 4
                self.save()
                return

        log.error("Could not find PT_GNU_STACK, stack should already be executable")
