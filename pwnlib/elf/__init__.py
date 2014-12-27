"""Exposes functionality for manipulating ELF files
"""
from ..term import text
from .datatypes import *
from ..asm import asm, disasm
from ..util import misc

import mmap, subprocess, os, logging
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.elf.descriptions import describe_e_type
from elftools.elf.constants import P_FLAGS, SHN_INDICES

log = logging.getLogger(__name__)

__all__ = ['load', 'ELF'] + sorted(filter(lambda x: not x.startswith('_'), datatypes.__dict__.keys()))

def load(*args, **kwargs):
    """Compatibility wrapper for pwntools v1"""
    return ELF(*args, **kwargs)

class ELF(ELFFile):
    """Encapsulates information about an ELF file.

    :ivar path: Path to the binary on disk
    :ivar symbols:  Dictionary of {name: address} for all symbols in the ELF
    :ivar plt:      Dictionary of {name: address} for all functions in the PLT
    :ivar got:      Dictionary of {name: address} for all function pointers in the GOT
    :ivar libs:     Dictionary of {path: address} for each shared object required to load the ELF

    Example:

    .. code-block:: python

       bash = ELF(which('bash'))
       hex(bash.symbols['read'])
       # 0x41dac0
       hex(bash.plt['read'])
       # 0x41dac0
       u32(bash.read(bash.got['read'], 4))
       # 0x41dac6
       print disasm(bash.read(bash.plt['read'],16), arch='amd64')
       # 0:   ff 25 1a 18 2d 00       jmp    QWORD PTR [rip+0x2d181a]        # 0x2d1820
       # 6:   68 59 00 00 00          push   0x59
       # b:   e9 50 fa ff ff          jmp    0xfffffffffffffa60
    """
    def __init__(self, path):
        # elftools uses the backing file for all reads and writes
        # in order to permit writing without being able to write to disk,
        # mmap() the file.
        self.file = open(path,'rb')
        self.mmap = mmap.mmap(self.file.fileno(), 0, access=mmap.ACCESS_COPY)

        super(ELF,self).__init__(self.mmap)

        self.path     = os.path.abspath(path)


        # Fix difference between elftools and pwntools
        self.arch = self.get_machine_arch().lower()
        if self.arch == 'x64':
            self.arch = 'amd64'


        self._populate_got_plt()
        self._populate_symbols()
        self._populate_libraries()

        if self.elftype == 'DYN':
            self._address = 0
        else:
            self._address = min(filter(bool, (s.header.p_vaddr for s in self.segments)))
        self.load_addr = self._address

        if self.execstack:
            log.info('Stack is executable!')

    def __repr__(self):
        return "ELF(%r)" % self.path

    @property
    def entry(self):
        """Entry point to the ELF"""
        return self.address + (self.header.e_entry - self.load_addr)
    entrypoint = entry
    start      = entry

    @property
    def elfclass(self):
        """ELF class (32 or 64).

        .. note::
            Set during ``ELFFile._identify_file``
        """
        return self._elfclass

    @elfclass.setter
    def elfclass(self, newvalue):
        self._elfclass = newvalue

    @property
    def elftype(self):
        """ELF type (EXEC, DYN, etc)"""
        return describe_e_type(self.header.e_type).split()[0]

    @property
    def segments(self):
        """A list of all segments in the ELF"""
        return list(self.iter_segments())

    @property
    def sections(self):
        """A list of all sections in the ELF"""
        return list(self.iter_sections())

    @property
    def dwarf(self):
        """DWARF info for the elf"""
        return self.get_dwarf_info()

    @property
    def address(self):
        """Address of the lowest segment loaded in the ELF.
        When updated, cascades updates to segment vaddrs, section addrs, symbols, plt, and got.

        >>> bash = ELF(which('bash'))
        >>> old = bash.symbols['read']
        >>> bash.address += 0x1000
        >>> bash.symbols['read'] == old + 0x1000
        True
        """
        return self._address

    @address.setter
    def address(self, new):
        delta     = new-self._address
        update    = lambda x: x+delta

        self.symbols = {k:update(v) for k,v in self.symbols.items()}
        self.plt     = {k:update(v) for k,v in self.plt.items()}
        self.got     = {k:update(v) for k,v in self.got.items()}

        self._address = update(self.address)

    def section(self, name):
        """Gets data for the named section

        Args:
            name(str): Name of the section

        Returns:
            String containing the bytes for that section
        """
        return self.get_section_by_name(name).data()

    @property
    def executable_segments(self):
        """Returns: list of all segments which are executable."""
        return [s for s in self.segments if s.header.p_flags & P_FLAGS.PF_X]

    @property
    def writable_segments(self):
        """Returns: list of all segments which are writeable"""
        return [s for s in self.segments if s.header.p_flags & P_FLAGS.PF_W]

    @property
    def non_writable_segments(self):
        """Returns: list of all segments which are NOT writeable"""
        return [s for s in self.segments if not s.header.p_flags & P_FLAGS.PF_W]

    def _populate_libraries(self):
        """
        >>> from os.path import exists
        >>> bash = ELF(which('bash'))
        >>> all(map(exists, bash.libs.keys()))
        True
        >>> any(map(lambda x: 'libc' in x, bash.libs.keys()))
        True
        """
        try:
            cmd = '(ulimit -s unlimited; ldd %s > /dev/null && (LD_TRACE_LOADED_OBJECTS=1 %s || ldd %s)) 2>/dev/null'
            arg = misc.sh_string(self.path)

            data = subprocess.check_output(cmd % (arg, arg, arg), shell = True)
            self.libs = misc.parse_ldd_output(data)
        except subprocess.CalledProcessError:
            self.libs = {}

    def _populate_symbols(self):
        """
        >>> bash = ELF(which('bash'))
        >>> bash.symbols['_start'] == bash.header.e_entry
        True
        """
        # By default, have 'symbols' include everything in the PLT.
        #
        # This way, elf.symbols['write'] will be a valid address to call
        # for write().
        self.symbols = dict(self.plt)

        for section in self.sections:
            if not isinstance(section, SymbolTableSection):
                continue

            for symbol in section.iter_symbols():
                if not symbol.entry.st_value:
                    continue

                self.symbols[symbol.name] = symbol.entry.st_value

        # Add 'plt.foo' and 'got.foo' to the symbols for entries,
        # iff there is no symbol for that address
        for sym, addr in self.plt.items():
            if addr not in self.symbols.values():
                self.symbols['plt.%s' % sym] = addr

        for sym, addr in self.got.items():
            if addr not in self.symbols.values():
                self.symbols['got.%s' % sym] = addr


    def _populate_got_plt(self):
        """Loads the GOT and the PLT symbols and addresses.

        The following doctest checks the valitidy of the addresses.
        This assumes that each GOT entry points to its PLT entry,
        usually +6 bytes but could be anywhere within 0-16 bytes.

        >>> from pwnlib.util.packing import unpack
        >>> bash = ELF(which('bash'))
        >>> def validate_got_plt(sym):
        ...     got      = bash.got[sym]
        ...     plt      = bash.plt[sym]
        ...     got_addr = unpack(bash.read(got, bash.elfclass/8), bash.elfclass)
        ...     return got_addr in range(plt,plt+0x10)
        ...
        >>> all(map(validate_got_plt, bash.got.keys()))
        True
        """
        plt = self.get_section_by_name('.plt')
        got = self.get_section_by_name('.got')

        self.got = {}
        self.plt = {}

        if not plt:
            return

        # Find the relocation section for PLT
        rel_plt = next(s for s in self.sections if s.header.sh_info == self.sections.index(plt))

        if rel_plt.header.sh_link != SHN_INDICES.SHN_UNDEF:
            # Find the symbols for the relocation section
            sym_rel_plt = self.sections[rel_plt.header.sh_link]

            # Populate the GOT
            for rel in rel_plt.iter_relocations():
                sym_idx  = rel.entry.r_info_sym
                symbol   = sym_rel_plt.get_symbol(sym_idx)
                name     = symbol.name

                self.got[name] = rel.entry.r_offset

        # Depending on the architecture, the beginning of the .plt will differ
        # in size, and each entry in the .plt will also differ in size.
        offset     = None
        multiplier = None

        # Map architecture: offset, multiplier
        header_size, entry_size = {
            'x86':   (0x10, 0x10),
            'amd64': (0x10, 0x10),
            'arm':   (0x14, 0xC)
        }[self.arch]


        # Based on the ordering of the GOT symbols, populate the PLT
        for i,(addr,name) in enumerate(sorted((addr,name) for name, addr in self.got.items())):
            self.plt[name] = plt.header.sh_addr + header_size + i*entry_size

    def search(self, needle, writable = False):
        """search(needle, writable = False) -> str generator

        Search the ELF's virtual address space for the specified string.

        Args:
            needle(str): String to search for.
            writable(bool): Search only writable sections.

        Returns:
            An iterator for each virtual address that matches.

        Examples:
            >>> bash = ELF(which('bash'))
            >>> bash.address + 1 == next(bash.search('ELF'))
            True

            >>> sh = ELF(which('bash'))
            >>> # /bin/sh should only depend on libc
            >>> libc_path = [key for key in sh.libs.keys() if 'libc' in key][0]
            >>> libc = ELF(libc_path)
            >>> # this string should be in there because of system(3)
            >>> len(list(libc.search('/bin/sh'))) > 0
            True
        """
        load_address_fixup = (self.address - self.load_addr)

        if writable:
            segments = self.writable_segments
        else:
            segments = self.segments

        for seg in segments:
            addr   = seg.header.p_vaddr
            data   = seg.data()
            offset = 0
            while True:
                offset = data.find(needle, offset)
                if offset == -1:
                    break
                yield (addr + offset + load_address_fixup)
                offset += 1

    def offset_to_vaddr(self, offset):
        """Translates the specified offset to a virtual address.

        Args:
            offset(int): Offset to translate

        Returns:
            Virtual address which corresponds to the file offset, or None

        Examples:
            >>> bash = ELF(which('bash'))
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


    def vaddr_to_offset(self, address):
        """Translates the specified virtual address to a file address

        Args:
            address(int): Virtual address to translate

        Returns:
            Offset within the ELF file which corresponds to the address,
            or None.

        Examples:
            >>> bash = ELF(which('bash'))
            >>> 0 == bash.vaddr_to_offset(bash.address)
            True
            >>> bash.address += 0x123456
            >>> 0 == bash.vaddr_to_offset(bash.address)
            True
        """
        load_address = address - self.address + self.load_addr

        for segment in self.segments:
            begin = segment.header.p_vaddr
            size  = segment.header.p_memsz
            end   = begin + size
            if begin <= load_address and load_address <= end:
                delta = load_address - begin
                return segment.header.p_offset + delta

        log.warning("Address %#x does not exist in %s" % (address, self.file.name))
        return None

    def read(self, address, count):
        """Read data from the specified virtual address

        Args:
            address(int): Virtual address to read
            count(int): Number of bytes to read

        Returns:
            A string of bytes, or None

        Examples:
          >>> bash = ELF(which('bash'))
          >>> bash.read(bash.address+1, 3)
          'ELF'
        """
        offset = self.vaddr_to_offset(address)

        if offset is not None:
            old = self.stream.tell()
            self.stream.seek(offset)
            data = self.stream.read(count)
            self.stream.seek(old)
            return data

        return None

    def write(self, address, data):
        """Writes data to the specified virtual address

        Args:
            address(int): Virtual address to write
            data(str): Bytes to write

        Note::
            This routine does not check the bounds on the write to ensure
            that it stays in the same segment.

        Examples:
          >>> bash = ELF(which('bash'))
          >>> bash.read(bash.address+1, 3)
          'ELF'
          >>> bash.write(bash.address, "HELO")
          >>> bash.read(bash.address, 4)
          'HELO'
        """
        offset = self.vaddr_to_offset(address)

        if offset is not None:
            old = self.stream.tell()
            self.stream.seek(offset)
            self.stream.write(data)
            self.stream.seek(old)

        return None

    def save(self, path):
        """Save the ELF to a file

        >>> bash = ELF(which('bash'))
        >>> bash.save('/tmp/bash_copy')
        >>> copy = file('/tmp/bash_copy')
        >>> bash = file(which('bash'))
        >>> bash.read() == copy.read()
        True
        """
        old = self.stream.tell()

        with open(path,'wb+') as fd:
            self.stream.seek(0)
            fd.write(self.get_data())

        self.stream.seek(old)

    def get_data(self):
        """Retrieve the raw data from the ELF file.

        >>> bash = ELF(which('bash'))
        >>> fd   = open(which('bash'))
        >>> bash.get_data() == fd.read()
        True
        """
        old = self.stream.tell()
        self.stream.seek(0)
        data = self.stream.read(self.stream.size())
        self.stream.seek(old)
        return data

    def disasm(self, address, n_bytes):
        """Returns a string of disassembled instructions at
        the specified virtual memory address"""
        return disasm(self.read(address, n_bytes), vma=address)

    def asm(self, address, assembly):
        """Assembles the specified instructions and inserts them
        into the ELF at the specified address.

        The resulting binary can be saved with ELF.save()
        """
        binary = asm(assembly, vma=address)
        self.write(address, binary)

    def bss(self, offset=0):
        """Returns an index into the .bss segment"""
        orig_bss = self.get_section_by_name('.bss').header.sh_addr
        curr_bss = orig_bss - self.load_addr + self.address
        return curr_bss + offset

    def __repr__(self):
        return "ELF(%r)" % self.path

    def dynamic_by_tag(self, tag):
        dt      = None
        dynamic = self.get_section_by_name('.dynamic')

        if not dynamic:
            return None

        try:
            dt = next(t for t in dynamic.iter_tags() if tag == t.entry.d_tag)
        except StopIteration:
            pass

        return dt

    def dynamic_string(self, offset):
        dt_strtab = self.dynamic_by_tag('DT_STRTAB')

        if not dt_strtab:
            return None

        address   = dt_strtab.entry.d_ptr + offset
        string    = ''
        while '\x00' not in string:
            string  += self.read(address, 1)
            address += 1
        return string.rstrip('\x00')


    @property
    def relro(self):
        if self.dynamic_by_tag('DT_BIND_NOW'):
            return "Full"

        if any('GNU_RELRO' in s.header.p_type for s in self.segments):
            return "Partial"
        return None

    @property
    def nx(self):
        return not any('GNU_STACK' in seg.header.p_type for seg in self.executable_segments)

    @property
    def execstack(self):
        return not self.nx

    @property
    def canary(self):
        return '__stack_chk_fail' in self.symbols

    @property
    def packed(self):
        return 'UPX!' in self.get_data()

    @property
    def pie(self):
        return self.elftype == 'DYN'
    aslr=pie

    @property
    def rpath(self):
        dt_rpath = self.dynamic_by_tag('DT_RPATH')

        if not dt_rpath:
            return None

        return self.dynamic_string(dt_rpath.entry.d_ptr)

    @property
    def runpath(self):
        dt_runpath = self.dynamic_by_tag('DT_RUNPATH')

        if not dt_runpath:
            return None

        return self.dynamic_string(dt_rpath.entry.d_ptr)

    def checksec(self, banner=True):
        red    = text.red
        green  = text.green
        yellow = text.yellow

        res = [
            "RELRO:".ljust(15) + {
                'Full':    green("Full RELRO"),
                'Partial': yellow("Partial RELRO"),
                None:      red("No RELRO")
            }[self.relro],
            "Stack Canary:".ljust(15) + {
                True:  green("Canary found"),
                False: red("No canary found")
            }[self.canary],
            "NX:".ljust(15) + {
                True:  green("NX enabled"),
                False: red("NX disabled"),
            }[self.nx],
            "PIE:".ljust(15) + {
                True: green("PIE enabled"),
                False: red("No PIE")
            }[self.pie],
            "RPATH:".ljust(15) + {
                False:  green("No RPATH"),
                True:   red(repr(self.rpath))
            }.get(bool(self.rpath)),
            "RUNPATH:".ljust(15) + {
                False:  green("No RUNPATH"),
                True:   red(repr(self.runpath))
            }.get(bool(self.runpath))
        ]

        if self.packed:
            res.append('Packer:'.ljust(15) + red("Packed with UPX"))

        return '\n'.join(res)

