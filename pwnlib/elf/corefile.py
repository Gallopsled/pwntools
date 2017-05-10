# -*- coding: utf-8 -*-
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
import glob
import gzip
import re
import os
import socket
import StringIO
import tempfile

import elftools
from elftools.common.py3compat import bytes2str
from elftools.common.utils import roundup
from elftools.common.utils import struct_parse
from elftools.construct import CString

from pwnlib import atexit
from pwnlib.context import context
from pwnlib.elf.datatypes import *
from pwnlib.elf.elf import ELF
from pwnlib.log import getLogger
from pwnlib.tubes.process import process
from pwnlib.tubes.ssh import ssh_channel
from pwnlib.tubes.tube import tube
from pwnlib.util.fiddling import b64d
from pwnlib.util.fiddling import unhex
from pwnlib.util.misc import read
from pwnlib.util.misc import write
from pwnlib.util.packing import pack
from pwnlib.util.packing import unpack_many

log = getLogger(__name__)

prstatus_types = {
    'i386': elf_prstatus_i386,
    'amd64': elf_prstatus_amd64,
    'arm': elf_prstatus_arm,
    'aarch64': elf_prstatus_aarch64
}

prpsinfo_types = {
    32: elf_prpsinfo_32,
    64: elf_prpsinfo_64,
}

siginfo_types = {
    32: elf_siginfo_32,
    64: elf_siginfo_64
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

        #: :class:`str`: Name of the mapping, e.g. ``'/bin/bash'`` or ``'[vdso]'``.
        self.name = name or ''

        #: :class:`int`: First mapped byte in the mapping
        self.start = start

        #: :class:`int`: First byte after the end of hte mapping
        self.stop = stop

        #: :class:`int`: Size of the mapping, in bytes
        self.size = stop-start

        #: :class:`int`: Mapping flags, using e.g. ``PROT_READ`` and so on.
        self.flags = flags

    @property
    def path(self):
        """:class:`str`: Alias for :attr:`.Mapping.name`"""
        return self.name

    @property
    def address(self):
        """:class:`int`: Alias for :data:`Mapping.start`."""
        return self.start

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

    def __getitem__(self, item):
        if isinstance(item, slice):
            start = int(item.start or self.start)
            stop  = int(item.stop or self.stop)

            # Negative slices...
            if start < 0:
                start += self.stop
            if stop < 0:
                stop += self.stop

            if not (self.start <= start <= stop <= self.stop):
                log.error("Byte range [%#x:%#x] not within range [%#x:%#x]" \
                    % (start, stop, self.start, self.stop))

            data = self._core.read(start, stop-start)

            if item.step == 1:
                return data
            return data[::item.step]

        return self._core.read(item, 1)

    def __contains__(self, item):
        return self.start <= item < self.stop

    def find(self, sub, start=None, end=None):
        """Similar to str.find() but works on our address space"""
        if start is None:
            start = self.start
        if end is None:
            end = self.stop

        result = self.data.find(sub, start-self.address, end-self.address)

        if result == -1:
            return result

        return result + self.address

    def rfind(self, sub, start=None, end=None):
        """Similar to str.rfind() but works on our address space"""
        if start is None:
            start = self.start
        if end is None:
            end = self.stop

        result = self.data.rfind(sub, start-self.address, end-self.address)

        if result == -1:
            return result

        return result + self.address

class Corefile(ELF):
    r"""Enhances the inforation available about a corefile (which is an extension
    of the ELF format) by permitting extraction of information about the mapped
    data segments, and register state.

    Registers can be accessed directly, e.g. via ``core_obj.eax`` and enumerated
    via :data:`Corefile.registers`.

    Arguments:
        core: Path to the core file.  Alternately, may be a :class:`.process` instance,
              and the core file will be located automatically.

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

    Example:

        The Linux kernel may not overwrite an existing core-file.

        >>> if os.path.exists('core'): os.unlink('core')

        Let's build an example binary which should eat ``R0=0xdeadbeef``
        and ``PC=0xcafebabe``.

        If we run the binary and then wait for it to exit, we can get its
        core file.

        >>> context.clear(arch='arm')
        >>> shellcode = shellcraft.mov('r0', 0xdeadbeef)
        >>> shellcode += shellcraft.mov('r1', 0xcafebabe)
        >>> shellcode += 'bx r1'
        >>> address = 0x41410000
        >>> elf = ELF.from_assembly(shellcode, vma=address)
        >>> io = elf.process(env={'HELLO': 'WORLD'})
        >>> io.poll(block=True)
        -11

        You can specify a full path a la ``Corefile('/path/to/core')``,
        but you can also just access the :attr:`.process.corefile` attribute.

        >>> core = io.corefile

        The core file has a :attr:`.Corefile.exe` property, which is a :class:`.Mapping`
        object.  Each mapping can be accessed with virtual addresses via subscript, or
        contents can be examined via the :attr:`.Mapping.data` attribute.

        >>> core.exe.address == address
        True

        The core file also has registers which can be accessed direclty.
        Pseudo-registers ``pc`` and ``sp`` are available on all architectures,
        to make writing architecture-agnostic code more simple.

        >>> core.pc == 0xcafebabe
        True
        >>> core.r0 == 0xdeadbeef
        True
        >>> core.sp == core.r13
        True

        We may not always know which signal caused the core dump, or what address
        caused a segmentation fault.  Instead of accessing registers directly, we
        can also extract this information from the core dump.

        On QEMU-generated core dumps, this information is unavailable, so we
        substitute the value of PC.  In our example, that's correct anyway.

        >>> core.fault_addr == 0xcafebabe
        True
        >>> core.signal
        11

        Core files can also be generated from running processes.
        This requires GDB to be installed, and can only be done with native
        processes.  Getting a "complete" corefile requires GDB 7.11 or better.

        >>> elf = ELF('/bin/bash')
        >>> context.clear(binary=elf)
        >>> io = process(elf.path, env={'HELLO': 'WORLD'})
        >>> core = io.corefile

        Data can also be extracted directly from the corefile.

        >>> core.exe[elf.address:elf.address+4]
        '\x7fELF'
        >>> core.exe.data[:4]
        '\x7fELF'

        Various other mappings are available by name.  On Linux, 32-bit Intel binaries
        should have a VDSO section.  Since our ELF is statically linked, there is
        no libc which gets mapped.

        >>> core.vdso.data[:4]
        '\x7fELF'
        >>> core.libc # docteset: +ELLIPSIS
        Mapping('/lib/x86_64-linux-gnu/libc-...', ...)

        The corefile also contains a :attr:`.Corefile.stack` property, which gives
        us direct access to the stack contents.  On Linux, the very top of the stack
        should contain two pointer-widths of NULL bytes, preceded by the NULL-
        terminated path to the executable (as passed via the first arg to ``execve``).

        >>> stack_end = core.exe.name
        >>> stack_end += '\x00' * (1+8)
        >>> core.stack.data.endswith(stack_end)
        True
        >>> len(core.stack.data) == core.stack.size
        True

        We can also directly access the environment variables and arguments.

        >>> 'HELLO' in core.env
        True
        >>> core.getenv('HELLO')
        'WORLD'
        >>> core.argc
        1
        >>> core.argv[0] in core.stack
        True
        >>> core.string(core.argv[0]) == core.exe.path
        True

        Corefiles can also be pulled from remote machines via SSH!

        >>> s = ssh('travis', 'example.pwnme')
        >>> _ = s.set_working_directory()
        >>> elf = ELF.from_assembly('int3')
        >>> path = s.upload(elf.path)
        >>> _ =s.chmod('+x', path)
        >>> io = s.process(path)
        >>> io.wait()
        -1
        >>> io.corefile.signal == signal.SIGTRAP # doctest: +SKIP
        True
    """

    _fill_gaps = False

    def __init__(self, *a, **kw):
        #: The NT_PRSTATUS object.
        self.prstatus = None

        #: The NT_PRPSINFO object
        self.prpsinfo = None

        #: The NT_SIGINFO object
        self.siginfo = None

        #: :class:`dict`: Dictionary of memory mappings from ``address`` to ``name``
        self.mappings = []

        #: :class:`int`: Address of the stack base
        self.stack    = None

        #: :class:`dict`: Environment variables read from the stack.  Keys are
        #: the environment variable name, values are the memory address of the
        #: variable.
        #:
        #: Note: Use with the :meth:`.ELF.string` method to extract them.
        self.env = {}

        #: :class:`list`: List of addresses of arguments on the stack.
        self.argv = []

        #: :class:`int`: Number of arguments passed
        self.argc = 0

        # Pointer to the executable filename on the stack
        self.at_execfn = 0

        # Pointer to the entry point
        self.at_entry = 0

        try:
            super(Corefile, self).__init__(*a, **kw)
        except IOError:
            log.warning("No corefile.  Have you set /proc/sys/kernel/core_pattern?")
            raise

        self.load_addr = 0
        self._address  = 0

        if not self.elftype == 'CORE':
            log.error("%s is not a valid corefile" % self.file.name)

        if not self.arch in prstatus_types.keys():
            log.warn_once("%s does not use a supported corefile architecture, registers are unavailable" % self.file.name)

        prstatus_type = prstatus_types.get(self.arch, None)
        prpsinfo_type = prpsinfo_types.get(self.bits, None)
        siginfo_type = siginfo_types.get(self.bits, None)

        with log.waitfor("Parsing corefile...") as w:
            self._load_mappings()

            for segment in self.segments:
                if not isinstance(segment, elftools.elf.segments.NoteSegment):
                    continue
                for note in iter_notes(segment):
                    # Try to find NT_PRSTATUS.  Note that pyelftools currently
                    # mis-identifies the enum name as 'NT_GNU_ABI_TAG'.
                    if prstatus_type and \
                       note.n_descsz == ctypes.sizeof(prstatus_type) and \
                       note.n_type == 'NT_GNU_ABI_TAG':
                        self.NT_PRSTATUS = note
                        self.prstatus = prstatus_type.from_buffer_copy(note.n_desc)

                    # Try to find NT_PRPSINFO
                    # Note that pyelftools currently mis-identifies the enum name
                    # as 'NT_GNU_BUILD_ID'
                    if note.n_descsz == ctypes.sizeof(prpsinfo_type) and \
                       note.n_type == 'NT_GNU_BUILD_ID':
                        self.NT_PRPSINFO = note
                        self.prpsinfo = prpsinfo_type.from_buffer_copy(note.n_desc)

                    # Try to find NT_SIGINFO so we can see the fault
                    if note.n_type == 0x53494749:
                        self.NT_SIGINFO = note
                        self.siginfo = siginfo_type.from_buffer_copy(note.n_desc)

                    # Try to find the list of mapped files
                    if note.n_type == constants.NT_FILE:
                        with context.local(bytes=self.bytes):
                            self._parse_nt_file(note)

                    # Try to find the auxiliary vector, which will tell us
                    # where the top of the stack is.
                    if note.n_type == constants.NT_AUXV:
                        with context.local(bytes=self.bytes):
                            self._parse_auxv(note)

            if not self.stack and self.mappings:
                self.stack = self.mappings[-1]

            if self.stack and self.mappings:
                for mapping in self.mappings:
                    if mapping.stop == self.stack:
                        mapping.name = '[stack]'
                        self.stack   = mapping
                        break
                else:
                    for mapping in self.mappings:
                        if self.stack in mapping:
                            mapping.name = '[stack]'
                            self.stack   = mapping
                            break
                    else:
                        log.warn('Could not find the stack!')
                        self.stack = None

            with context.local(bytes=self.bytes, log_level='error'):
                try:
                    self._parse_stack()
                except ValueError:
                    # If there are no environment variables, we die by running
                    # off the end of the stack.
                    pass

            self._describe_core()

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
        expr = r'libc\b.*so$'

        for m in self.mappings:
            if not m.name:
                continue

            basename = os.path.basename(m.name)

            if re.match(expr, basename):
                return m

    @property
    def exe(self):
        """:class:`Mapping`: First mapping for the executable file."""
        for m in self.mappings:
            if self.at_entry and m.start <= self.at_entry <= m.stop:

                if not m.name and self.at_execfn:
                    m.name = self.string(self.at_execfn)

                return m

    @property
    def pid(self):
        """:class:`int`: PID of the process which created the core dump."""
        if self.prstatus:
            return int(self.prstatus.pr_pid)

    @property
    def ppid(self):
        """:class:`int`: Parent PID of the process which created the core dump."""
        if self.prstatus:
            return int(self.prstatus.pr_ppid)

    @property
    def signal(self):
        """:class:`int`: Signal which caused the core to be dumped."""
        if self.siginfo:
            return int(self.siginfo.si_signo)
        if self.prstatus:
            return int(self.prstatus.pr_cursig)

    @property
    def fault_addr(self):
        """:class:`int`: Address which generated the fault, for the signals
            SIGILL, SIGFPE, SIGSEGV, SIGBUS.  This is only available in native
            core dumps created by the kernel.  If the information is unavailable,
            this returns the address of the instruction pointer."""
        if self.siginfo:
            return int(self.siginfo.sigfault_addr)

        return getattr(self, 'pc', 0)

    @property
    def _pc_register(self):
        name = {
            'i386': 'eip',
            'amd64': 'rip',
        }.get(self.arch, 'pc')
        return name

    @property
    def pc(self):
        """:class:`int`: The program counter for the Corefile

        This is a cross-platform way to get e.g. ``core.eip``, ``core.rip``, etc.
        """
        return self.registers.get(self._pc_register, None)

    @property
    def _sp_register(self):
        name = {
            'i386': 'esp',
            'amd64': 'rsp',
        }.get(self.arch, 'sp')
        return name

    @property
    def sp(self):
        """:class:`int`: The program counter for the Corefile

        This is a cross-platform way to get e.g. ``core.esp``, ``core.rsp``, etc.
        """
        return self.registers.get(self._sp_register, None)

    def _describe(self):
        pass

    def _describe_core(self):
        gnu_triplet = '-'.join(map(str, (self.arch, self.bits, self.endian)))

        fields = [
            repr(self.path),
            '%-10s %s' % ('Arch:', gnu_triplet),
            '%-10s %#x' % ('%s:' % self._pc_register.upper(), getattr(self, 'pc', 0)),
            '%-10s %#x' % ('%s:' % self._sp_register.upper(), getattr(self, 'sp', 0)),
        ]

        if self.exe and self.exe.name:
            fields += [
                '%-10s %s' % ('Exe:', '%r (%#x)' % (self.exe.name, self.exe.address))
            ]

        if self.fault_addr:
            fields += [
                '%-10s %#x' % ('Fault:', self.fault_addr)
            ]

        log.info_once('\n'.join(fields))

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
        # Get a copy of the stack mapping
        stack = self.stack

        if not stack:
            return

        # AT_EXECFN is the start of the filename, e.g. '/bin/sh'
        # Immediately preceding is a NULL-terminated environment variable string.
        # We want to find the beginning of it
        if self.at_execfn:
            address = self.at_execfn-1
        else:
            log.debug('No AT_EXECFN')
            address = stack.stop
            address -= 2*self.bytes
            address -= 1
            address = stack.rfind('\x00', None, address)
            address += 1

        # Sanity check!
        try:
            assert stack[address] == '\x00'
        except AssertionError:
            # Something weird is happening.  Just don't touch it.
            log.debug("Something is weird")
            return
        except ValueError:
            # If the stack is not actually present in the coredump, we can't
            # read from the stack.  This will fail as:
            # ValueError: 'seek out of range'
            log.debug("ValueError")
            return

        # address is currently set to the NULL terminator of the last
        # environment variable.
        address = stack.rfind('\x00', None, address)

        # We've found the beginning of the last environment variable.
        # We should be able to search up the stack for the envp[] array to
        # find a pointer to this address, followed by a NULL.
        last_env_addr = address + 1
        p_last_env_addr = stack.find(pack(last_env_addr), None, last_env_addr)

        # Sanity check that we did correctly find the envp NULL terminator.
        envp_nullterm = p_last_env_addr+context.bytes
        assert self.unpack(envp_nullterm) == 0

        # We've successfully located the end of the envp[] array.
        #
        # It comes immediately after the argv[] array, which itself
        # is NULL-terminated.
        #
        # Now let's find the end of argv
        p_end_of_argv = stack.rfind(pack(0), None, p_last_env_addr)

        start_of_envp = p_end_of_argv + self.bytes

        # Now we can fill in the environment
        env_pointer_data = stack[start_of_envp:p_last_env_addr+self.bytes]
        for pointer in unpack_many(env_pointer_data):
            end = stack.find('=', last_env_addr)

            if pointer in stack and end in stack:
                name = stack[pointer:end]
                self.env[name] = pointer

        # May as well grab the arguments off the stack as well.
        # argc comes immediately before argv[0] on the stack, but
        # we don't know what argc is.
        #
        # It is unlikely that argc is a valid stack address.
        address = p_end_of_argv - self.bytes
        while self.unpack(address) in stack:
            address -= self.bytes

        # address now points at argc
        self.argc = self.unpack(address)

        # we can extract all of the arguments as well
        self.argv = unpack_many(stack[address + self.bytes: p_end_of_argv])

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
        if not self.prstatus:
            return {}

        rv = {}

        for k in dir(self.prstatus.pr_reg):
            if k.startswith('_'):
                continue

            try:
                rv[k] = int(getattr(self.prstatus.pr_reg, k))
            except Exception:
                pass

        return rv

    def debug(self, *a, **kw):
        """Open the corefile under a debugger."""
        if a or kw:
            log.error("Arguments are not supported for %s.debug()" % self.__class__.__name__)

        import pwnlib.gdb
        pwnlib.gdb.attach(self, exe=self.exe.path)

    def __getattr__(self, attribute):
        if self.prstatus:
            if hasattr(self.prstatus, attribute):
                return getattr(self.prstatus, attribute)

            if hasattr(self.prstatus.pr_reg, attribute):
                return getattr(self.prstatus.pr_reg, attribute)

        return super(Corefile, self).__getattribute__(attribute)

    # Override routines which don't make sense for Corefiles
    def _populate_got(*a): pass
    def _populate_plt(*a): pass

class Core(Corefile):
    """Alias for :class:`.Corefile`"""

class Coredump(Corefile):
    """Alias for :class:`.Corefile`"""

class CorefileFinder(object):
    def __init__(self, proc):
        if proc.poll() is None:
            log.error("Process %i has not exited" % (process.pid))

        self.process = proc
        self.pid = proc.pid
        self.uid = proc.suid
        self.gid = proc.sgid
        self.exe = proc.executable
        self.basename = os.path.basename(self.exe)
        self.cwd = proc.cwd

        # XXX: Should probably break out all of this logic into
        #      its own class, so that we can support "file ops"
        #      locally, via SSH, and over ADB, in a transparent way.
        if isinstance(proc, process):
            self.read = read
            self.unlink = os.unlink
        elif isinstance(proc, ssh_channel):
            self.read = proc.parent.read
            self.unlink = proc.parent.unlink

        self.kernel_core_pattern = self.read('/proc/sys/kernel/core_pattern').strip()
        self.kernel_core_uses_pid = bool(int(self.read('/proc/sys/kernel/core_uses_pid')))

        log.debug("core_pattern: %r" % self.kernel_core_pattern)
        log.debug("core_uses_pid: %r" % self.kernel_core_uses_pid)

        self.interpreter = self.binfmt_lookup()

        log.debug("interpreter: %r" % self.interpreter)

        # If we have already located the corefile, we will
        # have renamed it to 'core.<pid>'
        core_path = 'core.%i' % (proc.pid)
        self.core_path = None

        if os.path.isfile(core_path):
            log.debug("Found core immediately: %r" % core_path)
            self.core_path = core_path

        # Try QEMU first, since it's unlikely to be a false-positive unless
        # there is a PID *and* filename collision.
        if not self.core_path:
            log.debug("Looking for QEMU corefile")
            self.core_path = self.qemu_corefile()

        # Check for native coredumps as a last resort
        if not self.core_path:
            log.debug("Looking for native corefile")
            self.core_path = self.native_corefile()

        if not self.core_path:
            return

        core_pid = self.load_core_check_pid()

        # Move the corefile if we're configured that way
        if context.rename_corefiles:
            new_path = 'core.%i' % core_pid
            if core_pid > 0 and new_path != self.core_path:
                write(new_path, self.read(self.core_path))
                self.core_path = new_path

        # Check the PID
        if core_pid != self.pid:
            log.warn("Corefile PID does not match! (got %i)" % core_pid)

        # Register the corefile for removal only if it's an exact match
        elif context.delete_corefiles:
            atexit.register(lambda: os.unlink(self.core_path))


    def load_core_check_pid(self):
        """Test whether a Corefile matches our process

        Speculatively load a Corefile without informing the user, so that we
        can check if it matches the process we're looking for.

        Arguments:
            path(str): Path to the corefile on disk

        Returns:
            `bool`: ``True`` if the Corefile matches, ``False`` otherwise.
        """

        try:
            with context.quiet:
                with tempfile.NamedTemporaryFile() as tmp:
                    tmp.write(self.read(self.core_path))
                    tmp.flush()
                    return Corefile(tmp.name).pid
        except Exception:
            pass

        return -1

    def apport_corefile(self):
        """Find the apport crash for the process, and extract the core file.

        Arguments:
            process(process): Process object we're looking for.

        Returns:
            `str`: Raw core file contents
        """
        crash_data = self.apport_read_crash_data()

        log.debug("Apport Crash Data:\n%s" % crash_data)

        if crash_data:
            return self.apport_crash_extract_corefile(crash_data)

    def apport_crash_extract_corefile(self, crashfile_data):
        """Extract a corefile from an apport crash file contents.

        Arguments:
            crashfile_data(str): Crash file contents

        Returns:
            `str`: Raw binary data for the core file, or ``None``.
        """
        file = StringIO.StringIO(crashfile_data)

        # Find the pid of the crashfile
        for line in file:
            if line.startswith(' Pid:'):
                pid = int(line.split()[-1])

                if pid == self.pid:
                    break
        else:
            # Could not find a " Pid:" line
            return

        # Find the CoreDump section
        for line in file:
            if line.startswith('CoreDump: base64'):
                break
        else:
            # Could not find the coredump data
            return

        # Get all of the base64'd lines
        chunks = []
        for line in file:
            if not line.startswith(' '):
                break
            chunks.append(b64d(line))

        # Smush everything together, then extract it
        compressed_data = ''.join(chunks)
        compressed_file = StringIO.StringIO(compressed_data)
        gzip_file = gzip.GzipFile(fileobj=compressed_file)
        core_data = gzip_file.read()

        return core_data

    def apport_read_crash_data(self):
        """Find the apport crash for the process

        Returns:
            `str`: Raw contents of the crash file or ``None``.
        """
        uid = self.uid
        crash_name = self.exe.replace('/', '_')

        crash_path = '/var/crash/%s.%i.crash' % (crash_name, uid)

        try:
            log.debug("Looking for Apport crash at %r" % crash_path)
            data = self.read(crash_path)
        except Exception:
            return None

        # Remove the crash file, so that future crashes will be captured
        try:
            self.unlink(crash_path)
        except Exception:
            pass

        return data

    def native_corefile(self):
        """Find the corefile for a native crash.

        Arguments:
            process(process): Process whose crash we should find.

        """
        if self.kernel_core_pattern.startswith('|'):
            log.debug("Checking for corefile (piped)")
            return self.native_corefile_pipe()

        log.debug("Checking for corefile (pattern)")
        return self.native_corefile_pattern()

    def native_corefile_pipe(self):
        """native_corefile_pipe(self) -> str
        """
        # We only support apport
        if '/apport' not in self.kernel_core_pattern:
            log.warn_once("Unsupported core_pattern: %r" % self.kernel_core_pattern)
            return None

        apport_core = self.apport_corefile()

        if apport_core:
            # Write the corefile to the local directory
            filename = 'core.%s.%i.apport' % (self.basename, self.pid)
            with open(filename, 'wb+') as f:
                f.write(apport_core)
            return filename

        # Pretend core_pattern was just 'core', and see if we come up with anything
        self.kernel_core_pattern = 'core'
        return self.native_corefile_pattern()

    def native_corefile_pattern(self):
        """
        %%  a single % character
        %c  core file size soft resource limit of crashing process (since Linux 2.6.24)
        %d  dump mode—same as value returned by prctl(2) PR_GET_DUMPABLE (since Linux 3.7)
        %e  executable filename (without path prefix)
        %E  pathname of executable, with slashes ('/') replaced by exclamation marks ('!') (since Linux 3.0).
        %g  (numeric) real GID of dumped process
        %h  hostname (same as nodename returned by uname(2))
        %i  TID of thread that triggered core dump, as seen in the PID namespace in which the thread resides (since Linux 3.18)
        %I  TID of thread that triggered core dump, as seen in the initial PID namespace (since Linux 3.18)
        %p  PID of dumped process, as seen in the PID namespace in which the process resides
        %P  PID of dumped process, as seen in the initial PID namespace (since Linux 3.12)
        %s  number of signal causing dump
        %t  time of dump, expressed as seconds since the Epoch, 1970-01-01 00:00:00 +0000 (UTC)
        %u  (numeric) real UID of dumped process
        """
        replace = {
            '%%': '%',
            '%e': self.basename,
            '%E': self.exe.replace('/', '!'),
            '%g': str(self.gid),
            '%h': socket.gethostname(),
            '%i': str(self.pid),
            '%I': str(self.pid),
            '%p': str(self.pid),
            '%P': str(self.pid),
            '%s': str(-self.process.poll()),
            '%u': str(self.uid)
        }
        replace = dict((re.escape(k), v) for k, v in replace.iteritems())
        pattern = re.compile("|".join(replace.keys()))
        core_pattern = self.kernel_core_pattern
        corefile_path = pattern.sub(lambda m: replace[re.escape(m.group(0))], core_pattern)

        if self.kernel_core_uses_pid:
            corefile_path += '.%i' % self.pid

        if os.pathsep not in corefile_path:
            corefile_path = os.path.join(self.cwd, corefile_path)

        log.debug("Trying corefile_path: %r" % corefile_path)

        try:
            self.read(corefile_path)
            return corefile_path
        except Exception as e:
            log.debug("No dice: %s" % e)

    def qemu_corefile(self):
        """qemu_corefile() -> str

        Retrieves the path to a QEMU core dump.
        """

        # QEMU doesn't follow anybody else's rules
        # https://github.com/qemu/qemu/blob/stable-2.6/linux-user/elfload.c#L2710-L2744
        #
        #     qemu_<basename-of-target-binary>_<date>-<time>_<pid>.core
        #
        # Note that we don't give any fucks about the date and time, since the PID
        # should be unique enough that we can just glob.
        corefile_name = 'qemu_{basename}_*_{pid}.core'

        # Format the name
        corefile_name = corefile_name.format(basename=self.basename,
                                             pid=self.pid)

        # Get the full path
        corefile_path = os.path.join(self.cwd, corefile_name)

        log.debug("Trying corefile_path: %r" % corefile_path)

        # Glob all of them, return the *most recent* based on numeric sort order.
        for corefile in sorted(glob.glob(corefile_path), reverse=True):
            return corefile

    def binfmt_lookup(self):
        """Parses /proc/sys/fs/binfmt_misc to find the interpreter for a file"""

        binfmt_misc = '/proc/sys/fs/binfmt_misc'

        if not isinstance(self.process, process):
            log.debug("Not a process")
            return ''

        if self.process._qemu:
            return self.process._qemu

        if not os.path.isdir(binfmt_misc):
            log.debug("No binfmt_misc dir")
            return ''

        exe_data = bytearray(self.read(self.exe))

        for entry in os.listdir(binfmt_misc):
            keys = {}

            path = os.path.join(binfmt_misc, entry)

            try:
                data = self.read(path)
            except Exception:
                continue

            for line in data.splitlines():
                try:
                    k,v = line.split(None)
                except ValueError:
                    continue

                keys[k] = v

            if 'magic' not in keys:
                continue

            magic = bytearray(unhex(keys['magic']))
            mask  = bytearray('\xff' * len(magic))

            if 'mask' in keys:
                mask = bytearray(unhex(keys['mask']))

            for i, mag in enumerate(magic):
                if exe_data[i] & mask[i] != mag:
                    break
            else:
                return keys['interpreter']

        return ''

