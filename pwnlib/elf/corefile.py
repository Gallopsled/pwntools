import collections
import ctypes

import elftools
from elftools.common.py3compat import bytes2str
from elftools.common.utils import roundup
from elftools.common.utils import struct_parse
from elftools.construct import CString

from ..context import context
from ..log import getLogger
from ..tubes.tube import tube
from .datatypes import *
from .elf import ELF

log = getLogger(__name__)

types = {
    'i386': elf_prstatus_i386,
    'amd64': elf_prstatus_amd64,
    'arm': elf_prstatus_arm
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
            self._elfstructs.Elf_Nhdr,
            self.stream,
            stream_pos=offset)
        note['n_offset'] = offset
        offset += self._elfstructs.Elf_Nhdr.sizeof()
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
    def __init__(self, core, name, start, stop, flags):
        self._core=core
        self.name=name
        self.start=start
        self.stop=stop
        self.size=stop-start
        self.flags=flags
    @property
    def permstr(self):
        flags = self.flags
        return ''.join(['r' if flags & 4 else '-',
                        'w' if flags & 2 else '-',
                        'x' if flags & 1 else '-',
                        'p'])
    def __str__(self):
        return '%x-%x %s %x %s' % (self.start,self.stop,self.permstr,self.size,self.name)

    def __repr__(self):
        return '%s(%r, %#x, %#x, %#x, %#x)' % (self.__class__.__name__,
                                               self.name,
                                               self.start,
                                               self.stop,
                                               self.size,
                                               self.flags)

    def __int__(self):
        return self.start

    @property
    def data(self):
        return self._core.read(self.start, self.size)

class Core(ELF):
    """Core(*a, **kw) -> Core

    Enhances the inforation available about a corefile (which is an extension
    of the ELF format) by permitting extraction of information about the mapped
    data segments, and register state.

    Registers can be accessed directly, e.g. via ``core_obj.eax``.

    Mappings can be iterated in order via ``core_obj.mappings``.
    """
    def __init__(self, *a, **kw):
        #: The NT_PRSTATUS object.
        self.prstatus = None

        #: Dictionary of memory mappings from {address:name}
        self.mappings = []

        #: Address of the stack base
        self.stack    = None

        #: Environment variables read from the stack {name:address}.
        #: N.B. Use with the ``string`` method to extract them.
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

        if not self.arch in ('i386','amd64','arm'):
            log.error("%s does not use a supported corefile architecture" % self.file.name)

        prstatus_type = types[self.arch]

        with log.waitfor("Parsing corefile...") as w:
            self._load_mappings()

            # Attempt to detect broken QEMU corefiles
            if self.file.name.startswith('qemu') \
            and any(m.stop > (1 << self.bits) for m in self.mappings):
                log.warn_once("Broken QEMU corefile may have invalid memory mappings.  Use a newer QEMU.\n" +
                    "Consider using the most recent statically-linked package from Ubuntu.\n" +
                    "http://security.ubuntu.com/ubuntu/pool/universe/q/qemu/\n" +
                    "$ sudo dpkg -i qemu-user-static-foobar.deb")

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

            if self.stack_end and self.mappings:
                for mapping in self.mappings:
                    if mapping.stop == self.stack_end:
                        mapping.name = '[stack]'
                        self.stack   = mapping

            with context.local(bytes=self.bytes, log_level='error'):
                try:
                    self._parse_stack()
                except (ValueError, AttributeError):
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
        """Return the mapping for the vvar"""
        for m in self.mappings:
            if m.name == '[vvar]':
                return m

    @property
    def vdso(self):
        """Return the mapping for the vdso"""
        for m in self.mappings:
            if m.name == '[vdso]':
                return m

    @property
    def vsyscall(self):
        """Return the mapping for the vdso"""
        for m in self.mappings:
            if m.name == '[vsyscall]':
                return m

    @property
    def libc(self):
        """Return the first mapping in libc"""
        for m in self.mappings:
            if m.name.startswith('libc') and m.name.endswith('.so'):
                return m

    @property
    def exe(self):
        """Return the first mapping in the executable file."""
        for m in self.mappings:
            if self.at_entry and m.start <= self.at_entry <= m.stop:
                return m

    @property
    def entry(self):
        return self.at_entry

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

        for k in AT_CONSTANTS.values():
            setattr(self, k.lower(), None)

        for i in range(0, note.n_descsz, context.bytes * 2):
            key = t.unpack()
            value = t.unpack()
            name = AT_CONSTANTS.get(key, None)

            if name:
                setattr(self, name.lower(), value)

        # The AT_EXECFN entry is a pointer to the executable's filename
        # at the very top of the stack, followed by a word's with of
        # NULL bytes.  For example, on a 64-bit system...
        #
        # 0x7fffffffefe8  53 3d 31 34  33 00 2f 62  69 6e 2f 62  61 73 68 00  |S=14|3./b|in/b|ash.|
        # 0x7fffffffeff8  00 00 00 00  00 00 00 00                            |....|....|    |    |
        if self.at_execfn:
            value = self.at_execfn & ~0xfff
            value += 0x1000
            self.stack_end = value

        # The AT_RANDOM entry is a pointer to random data for use by libc.
        # However, the only place that it can be mapped is on the stack,
        # so it's a pointer to the stack.
        elif self.at_random:
            for m in self.mappings:
                if m.start <= self.at_random <= m.stop:
                    self.stack_end = m.stop

    def _parse_stack(self):
        # The end of the stack has AT_EXECFN, and is immediately preceded by the
        # environment.
        address = self.stack_end - 1

        # Rewind past AT_EXECFN.  This will be a handful of NUL bytes, then the
        # filename, then the end of the last environment variable (which ends with a NUL).
        while self.u8(address) == 0:
            address -= 1
        while self.u8(address) != 0:
            address -= 1

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
        """A printable string which is similar to /proc/xx/maps."""
        return '\n'.join(map(str, self.mappings))

    def getenv(self, name):
        """getenv(name) -> int

        Read an environment variable off the stack, and return its address.

        Arguments:
            name(str): Name of the environment variable to read.

        Returns:
            The address of the environment variable.
        """
        if name not in self.env:
            log.error("Environment variable %r not set" % name)

        return self.string(self.env[name]).split('=',1)[-1]

    def __getattr__(self, attribute):
        if self.prstatus:
            if hasattr(self.prstatus, attribute):
                return getattr(self.prstatus, attribute)

            if hasattr(self.prstatus.pr_reg, attribute):
                return getattr(self.prstatus.pr_reg, attribute)

        return super(Core, self).__getattribute__(attribute)
