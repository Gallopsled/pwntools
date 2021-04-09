r"""
Return Oriented Programming

Manual ROP
-------------------

The ROP tool can be used to build stacks pretty trivially.
Let's create a fake binary which has some symbols which might
have been useful.

    >>> context.clear(arch='i386')
    >>> binary = ELF.from_assembly('add esp, 0x10; ret')
    >>> binary.symbols = {'read': 0xdeadbeef, 'write': 0xdecafbad, 'execve': 0xcafebabe, 'exit': 0xfeedface}

Creating a ROP object which looks up symbols in the binary is
pretty straightforward.

    >>> rop = ROP(binary)

With the ROP object, you can manually add stack frames.

    >>> rop.raw(0)
    >>> rop.raw(unpack(b'abcd'))
    >>> rop.raw(2)

Inspecting the ROP stack is easy, and laid out in an easy-to-read
manner.

    >>> print(rop.dump())
    0x0000:              0x0
    0x0004:       0x64636261
    0x0008:              0x2

The ROP module is also aware of how to make function calls with
standard Linux ABIs.

    >>> rop.call('read', [4,5,6])
    >>> print(rop.dump())
    0x0000:              0x0
    0x0004:       0x64636261
    0x0008:              0x2
    0x000c:       0xdeadbeef read(4, 5, 6)
    0x0010:          b'eaaa' <return address>
    0x0014:              0x4 arg0
    0x0018:              0x5 arg1
    0x001c:              0x6 arg2

You can also use a shorthand to invoke calls.
The stack is automatically adjusted for the next frame

    >>> rop.write(7,8,9)
    >>> rop.exit()
    >>> print(rop.dump())
    0x0000:              0x0
    0x0004:       0x64636261
    0x0008:              0x2
    0x000c:       0xdeadbeef read(4, 5, 6)
    0x0010:       0x10000000 <adjust @0x24> add esp, 0x10; ret
    0x0014:              0x4 arg0
    0x0018:              0x5 arg1
    0x001c:              0x6 arg2
    0x0020:          b'iaaa' <pad>
    0x0024:       0xdecafbad write(7, 8, 9)
    0x0028:       0x10000000 <adjust @0x3c> add esp, 0x10; ret
    0x002c:              0x7 arg0
    0x0030:              0x8 arg1
    0x0034:              0x9 arg2
    0x0038:          b'oaaa' <pad>
    0x003c:       0xfeedface exit()

You can also append complex arguments onto stack when the stack pointer is known.

    >>> rop = ROP(binary, base=0x7fffe000)
    >>> rop.call('execve', ['/bin/sh', [['/bin/sh'], ['-p'], ['-c'], ['ls']], 0])
    >>> print(rop.dump())
    0x7fffe000:       0xcafebabe execve(['/bin/sh'], [['/bin/sh'], ['-p'], ['-c'], ['ls']], 0)
    0x7fffe004:          b'baaa' <return address>
    0x7fffe008:       0x7fffe014 arg0 (+0xc)
    0x7fffe00c:       0x7fffe01c arg1 (+0x10)
    0x7fffe010:              0x0 arg2
    0x7fffe014:   b'/bin/sh\x00'
    0x7fffe01c:       0x7fffe02c (+0x10)
    0x7fffe020:       0x7fffe034 (+0x14)
    0x7fffe024:       0x7fffe038 (+0x14)
    0x7fffe028:       0x7fffe03c (+0x14)
    0x7fffe02c:   b'/bin/sh\x00'
    0x7fffe034:       b'-p\x00$'
    0x7fffe038:       b'-c\x00$'
    0x7fffe03c:       b'ls\x00$'

ROP also detects 'jmp $sp' gadget to help exploit binaries with NX disabled.
You can get this gadget on 'i386':

    >>> context.clear(arch='i386')
    >>> elf = ELF.from_assembly('nop; jmp esp; ret')
    >>> rop = ROP(elf)
    >>> jmp_gadget = rop.jmp_esp
    >>> elf.read(jmp_gadget.address, 2) == asm('jmp esp')
    True

You can also get this gadget on 'amd64':

    >>> context.clear(arch='amd64')
    >>> elf = ELF.from_assembly('nop; jmp rsp; ret')
    >>> rop = ROP(elf)
    >>> jmp_gadget = rop.jmp_rsp
    >>> elf.read(jmp_gadget.address, 2) == asm('jmp rsp')
    True

Gadgets whose address has badchar are filtered out:

    >>> context.clear(arch='i386')
    >>> elf = ELF.from_assembly('nop; pop eax; jmp esp; int 0x80; jmp esp; ret')
    >>> rop = ROP(elf, badchars=b'\x02')
    >>> jmp_gadget = rop.jmp_esp    # It returns the second gadget
    >>> elf.read(jmp_gadget.address, 2) == asm('jmp esp')
    True
    >>> rop = ROP(elf, badchars=b'\x02\x06')
    >>> rop.jmp_esp == None         # The address of both gadgets has badchar
    True

ROP Example
-------------------

Let's assume we have a trivial binary that just reads some data
onto the stack, and returns.

    >>> context.clear(arch='i386')
    >>> c = constants
    >>> assembly =  'read:'      + shellcraft.read(c.STDIN_FILENO, 'esp', 1024)
    >>> assembly += 'ret\n'

Let's provide some simple gadgets:

    >>> assembly += 'add_esp: add esp, 0x10; ret\n'

And perhaps a nice "write" function.

    >>> assembly += 'write: enter 0,0\n'
    >>> assembly += '    mov ebx, [ebp+4+4]\n'
    >>> assembly += '    mov ecx, [ebp+4+8]\n'
    >>> assembly += '    mov edx, [ebp+4+12]\n'
    >>> assembly += shellcraft.write('ebx', 'ecx', 'edx')
    >>> assembly += '    leave\n'
    >>> assembly += '    ret\n'
    >>> assembly += 'flag: .asciz "The flag"\n'

And a way to exit cleanly.

    >>> assembly += 'exit: ' + shellcraft.exit(0)
    >>> binary   = ELF.from_assembly(assembly)

Finally, let's build our ROP stack

    >>> rop = ROP(binary)
    >>> rop.write(c.STDOUT_FILENO, binary.symbols['flag'], 8)
    >>> rop.exit()
    >>> print(rop.dump())
    0x0000:       0x10000012 write(STDOUT_FILENO, 0x10000026, 8)
    0x0004:       0x1000000e <adjust @0x18> add esp, 0x10; ret
    0x0008:              0x1 STDOUT_FILENO
    0x000c:       0x10000026 flag
    0x0010:              0x8 arg2
    0x0014:          b'faaa' <pad>
    0x0018:       0x1000002f exit()

The raw data from the ROP stack is available via `str`.

    >>> raw_rop = rop.chain()
    >>> print(enhex(raw_rop))
    120000100e000010010000002600001008000000666161612f000010

Let's try it out!

    >>> p = process(binary.path)
    >>> p.send(raw_rop)
    >>> print(repr(p.recvall(timeout=5)))
    b'The flag'

ROP Example (amd64)
-------------------

For amd64 binaries, the registers are loaded off the stack.  Pwntools can do
basic reasoning about simple "pop; pop; add; ret"-style gadgets, and satisfy
requirements so that everything "just works".

    >>> context.clear(arch='amd64')
    >>> assembly = 'pop rdx; pop rdi; pop rsi; add rsp, 0x20; ret; target: ret'
    >>> binary = ELF.from_assembly(assembly)
    >>> rop = ROP(binary)
    >>> rop.target(1,2,3)
    >>> print(rop.dump())
    0x0000:       0x10000000 pop rdx; pop rdi; pop rsi; add rsp, 0x20; ret
    0x0008:              0x3 [arg2] rdx = 3
    0x0010:              0x1 [arg0] rdi = 1
    0x0018:              0x2 [arg1] rsi = 2
    0x0020:      b'iaaajaaa' <pad 0x20>
    0x0028:      b'kaaalaaa' <pad 0x18>
    0x0030:      b'maaanaaa' <pad 0x10>
    0x0038:      b'oaaapaaa' <pad 0x8>
    0x0040:       0x10000008 target
    >>> rop.target(1)
    >>> print(rop.dump())
    0x0000:       0x10000000 pop rdx; pop rdi; pop rsi; add rsp, 0x20; ret
    0x0008:              0x3 [arg2] rdx = 3
    0x0010:              0x1 [arg0] rdi = 1
    0x0018:              0x2 [arg1] rsi = 2
    0x0020:      b'iaaajaaa' <pad 0x20>
    0x0028:      b'kaaalaaa' <pad 0x18>
    0x0030:      b'maaanaaa' <pad 0x10>
    0x0038:      b'oaaapaaa' <pad 0x8>
    0x0040:       0x10000008 target
    0x0048:       0x10000001 pop rdi; pop rsi; add rsp, 0x20; ret
    0x0050:              0x1 [arg0] rdi = 1
    0x0058:      b'waaaxaaa' <pad rsi>
    0x0060:      b'yaaazaab' <pad 0x20>
    0x0068:      b'baabcaab' <pad 0x18>
    0x0070:      b'daabeaab' <pad 0x10>
    0x0078:      b'faabgaab' <pad 0x8>
    0x0080:       0x10000008 target

Pwntools will also filter out some bad instructions while setting the registers
( e.g. syscall, int 0x80... )

    >>> assembly = 'syscall; pop rdx; pop rsi; ret ; pop rdi ; int 0x80; pop rsi; pop rdx; ret ; pop rdi ; ret'
    >>> binary = ELF.from_assembly(assembly)
    >>> rop = ROP(binary)
    >>> rop.call(0xdeadbeef, [1, 2, 3])
    >>> print(rop.dump())
    0x0000:       0x1000000b pop rdi; ret
    0x0008:              0x1 [arg0] rdi = 1
    0x0010:       0x10000002 pop rdx; pop rsi; ret
    0x0018:              0x3 [arg2] rdx = 3
    0x0020:              0x2 [arg1] rsi = 2
    0x0028:       0xdeadbeef

ROP + Sigreturn
-----------------------

In some cases, control of the desired register is not available.
However, if you have control of the stack, EAX, and can find a
`int 0x80` gadget, you can use sigreturn.

Even better, this happens automagically.

Our example binary will read some data onto the stack, and
not do anything else interesting.

    >>> context.clear(arch='i386')
    >>> c = constants
    >>> assembly =  'read:'      + shellcraft.read(c.STDIN_FILENO, 'esp', 1024)
    >>> assembly += 'ret\n'
    >>> assembly += 'pop eax; ret\n'
    >>> assembly += 'int 0x80\n'
    >>> assembly += 'binsh: .asciz "/bin/sh"'
    >>> binary    = ELF.from_assembly(assembly)

Let's create a ROP object and invoke the call.

    >>> context.kernel = 'amd64'
    >>> rop   = ROP(binary)
    >>> binsh = binary.symbols['binsh']
    >>> rop.execve(binsh, 0, 0)

That's all there is to it.

    >>> print(rop.dump())
    0x0000:       0x1000000e pop eax; ret
    0x0004:             0x77 [arg0] eax = SYS_sigreturn
    0x0008:       0x1000000b int 0x80; ret
    0x000c:              0x0 gs
    0x0010:              0x0 fs
    0x0014:              0x0 es
    0x0018:              0x0 ds
    0x001c:              0x0 edi
    0x0020:              0x0 esi
    0x0024:              0x0 ebp
    0x0028:              0x0 esp
    0x002c:       0x10000012 ebx = binsh
    0x0030:              0x0 edx
    0x0034:              0x0 ecx
    0x0038:              0xb eax = SYS_execve
    0x003c:              0x0 trapno
    0x0040:              0x0 err
    0x0044:       0x1000000b int 0x80; ret
    0x0048:             0x23 cs
    0x004c:              0x0 eflags
    0x0050:              0x0 esp_at_signal
    0x0054:             0x2b ss
    0x0058:              0x0 fpstate

Let's try it out!

    >>> p = process(binary.path)
    >>> p.send(rop.chain())
    >>> time.sleep(1)
    >>> p.sendline(b'echo hello; exit')
    >>> p.recvline()
    b'hello\n'
"""
from __future__ import absolute_import
from __future__ import division

import collections
import copy
import hashlib
import itertools
import os
import re
import shutil
import six
import string
import sys
import tempfile

from pwnlib import abi
from pwnlib import constants
from pwnlib.context import LocalContext
from pwnlib.context import context
from pwnlib.elf import ELF
from pwnlib.log import getLogger
from pwnlib.rop import srop
from . import ret2dlresolve
from pwnlib.rop.call import AppendedArgument
from pwnlib.rop.call import Call
from pwnlib.rop.call import CurrentStackPointer
from pwnlib.rop.call import NextGadgetAddress
from pwnlib.rop.call import StackAdjustment
from pwnlib.rop.call import Unresolved
from pwnlib.rop.gadgets import Gadget
from pwnlib.util import lists
from pwnlib.util import packing
from pwnlib.util.cyclic import cyclic
from pwnlib.util.packing import pack
from pwnlib.util.misc import python_2_bytes_compatible

log = getLogger(__name__)
__all__ = ['ROP']

enums = Call, constants.Constant
try:
    from enum import Enum
except ImportError:
    pass
else:
    enums += Enum,

class Padding(object):
    """
    Placeholder for exactly one pointer-width of padding.
    """
    def __init__(self, name='<pad>'):
        self.name = name

def _slot_len(x):
    if isinstance(x, six.integer_types+(Unresolved, Padding, Gadget)):
        return context.bytes
    else:
        return len(packing.flat(x))

class DescriptiveStack(list):
    """
    List of resolved ROP gadgets that correspond to the ROP calls that
    the user has specified.
    """

    #: Base address
    address = 0

    #: Dictionary of \`{address: [list of descriptions]}`
    descriptions = {}

    def __init__(self, address):
        self.descriptions = collections.defaultdict(list)
        self.address      = address or 0
        self._next_next   = 0
        self._next_last   = 0

    @property
    def next(self):
        for x in self[self._next_last:]:
            self._next_next += _slot_len(x)
        self._next_last = len(self)
        return self.address + self._next_next

    def describe(self, text, address = None):
        if address is None:
            address = self.next
        self.descriptions[address] = text

    def dump(self):
        rv = []
        addr = self.address
        for i, data in enumerate(self):
            off = None
            line = '0x%04x:' % addr
            if isinstance(data, (str, bytes)):
                line += ' %16r' % data
            elif isinstance(data, six.integer_types):
                line += ' %#16x' % data
                if self.address != 0 and self.address < data < self.next:
                    off = data - addr
            else:
                log.error("Don't know how to dump %r" % data)
            desc = self.descriptions.get(addr, '')
            if desc:
                line += ' %s' % desc
            if off is not None:
                line += ' (+%#x)' % off
            rv.append(line)
            addr += _slot_len(data)

        return '\n'.join(rv)


@python_2_bytes_compatible
class ROP(object):
    r"""Class which simplifies the generation of ROP-chains.

    Example:

    .. code-block:: python

       elf = ELF('ropasaurusrex')
       rop = ROP(elf)
       rop.read(0, elf.bss(0x80))
       rop.dump()
       # ['0x0000:        0x80482fc (read)',
       #  '0x0004:       0xdeadbeef',
       #  '0x0008:              0x0',
       #  '0x000c:        0x80496a8']
       bytes(rop)
       # '\xfc\x82\x04\x08\xef\xbe\xad\xde\x00\x00\x00\x00\xa8\x96\x04\x08'

    >>> context.clear(arch = "i386", kernel = 'amd64')
    >>> assembly = 'int 0x80; ret; add esp, 0x10; ret; pop eax; ret'
    >>> e = ELF.from_assembly(assembly)
    >>> e.symbols['funcname'] = e.entry + 0x1234
    >>> r = ROP(e)
    >>> r.funcname(1, 2)
    >>> r.funcname(3)
    >>> r.execve(4, 5, 6)
    >>> print(r.dump())
    0x0000:       0x10001234 funcname(1, 2)
    0x0004:       0x10000003 <adjust @0x18> add esp, 0x10; ret
    0x0008:              0x1 arg0
    0x000c:              0x2 arg1
    0x0010:          b'eaaa' <pad>
    0x0014:          b'faaa' <pad>
    0x0018:       0x10001234 funcname(3)
    0x001c:       0x10000007 <adjust @0x24> pop eax; ret
    0x0020:              0x3 arg0
    0x0024:       0x10000007 pop eax; ret
    0x0028:             0x77 [arg0] eax = SYS_sigreturn
    0x002c:       0x10000000 int 0x80; ret
    0x0030:              0x0 gs
    0x0034:              0x0 fs
    0x0038:              0x0 es
    0x003c:              0x0 ds
    0x0040:              0x0 edi
    0x0044:              0x0 esi
    0x0048:              0x0 ebp
    0x004c:              0x0 esp
    0x0050:              0x4 ebx
    0x0054:              0x6 edx
    0x0058:              0x5 ecx
    0x005c:              0xb eax = SYS_execve
    0x0060:              0x0 trapno
    0x0064:              0x0 err
    0x0068:       0x10000000 int 0x80; ret
    0x006c:             0x23 cs
    0x0070:              0x0 eflags
    0x0074:              0x0 esp_at_signal
    0x0078:             0x2b ss
    0x007c:              0x0 fpstate

    >>> r = ROP(e, 0x8048000)
    >>> r.funcname(1, 2)
    >>> r.funcname(3)
    >>> r.execve(4, 5, 6)
    >>> print(r.dump())
    0x8048000:       0x10001234 funcname(1, 2)
    0x8048004:       0x10000003 <adjust @0x8048018> add esp, 0x10; ret
    0x8048008:              0x1 arg0
    0x804800c:              0x2 arg1
    0x8048010:          b'eaaa' <pad>
    0x8048014:          b'faaa' <pad>
    0x8048018:       0x10001234 funcname(3)
    0x804801c:       0x10000007 <adjust @0x8048024> pop eax; ret
    0x8048020:              0x3 arg0
    0x8048024:       0x10000007 pop eax; ret
    0x8048028:             0x77 [arg0] eax = SYS_sigreturn
    0x804802c:       0x10000000 int 0x80; ret
    0x8048030:              0x0 gs
    0x8048034:              0x0 fs
    0x8048038:              0x0 es
    0x804803c:              0x0 ds
    0x8048040:              0x0 edi
    0x8048044:              0x0 esi
    0x8048048:              0x0 ebp
    0x804804c:        0x8048080 esp
    0x8048050:              0x4 ebx
    0x8048054:              0x6 edx
    0x8048058:              0x5 ecx
    0x804805c:              0xb eax = SYS_execve
    0x8048060:              0x0 trapno
    0x8048064:              0x0 err
    0x8048068:       0x10000000 int 0x80; ret
    0x804806c:             0x23 cs
    0x8048070:              0x0 eflags
    0x8048074:              0x0 esp_at_signal
    0x8048078:             0x2b ss
    0x804807c:              0x0 fpstate


    >>> elf = ELF.from_assembly('ret')
    >>> r = ROP(elf)
    >>> r.ret.address == 0x10000000
    True
    >>> r = ROP(elf, badchars=b'\x00')
    >>> r.gadgets == {}
    True
    >>> r.ret is None
    True
    """
    BAD_ATTRS = [
        'trait_names',          # ipython tab-complete
        'download',             # frequent typo
        'upload',               # frequent typo
    ]
    X86_SUFFIXES = ['ax', 'bx', 'cx', 'dx', 'bp', 'sp', 'di', 'si',
                    'r8', 'r9', '10', '11', '12', '13', '14', '15']

    def __init__(self, elfs, base = None, badchars = b'', **kwargs):
        """
        Arguments:
            elfs(list): List of :class:`.ELF` objects for mining
            base(int): Stack address where the first byte of the ROP chain lies, if known.
            badchars(str): Characters which should not appear in ROP gadget addresses.
        """
        import ropgadget

        # Permit singular ROP(elf) vs ROP([elf])
        if isinstance(elfs, ELF):
            elfs = [elfs]
        elif isinstance(elfs, (bytes, six.text_type)):
            elfs = [ELF(elfs)]

        #: List of individual ROP gadgets, ROP calls, SROP frames, etc.
        #: This is intended to be the highest-level abstraction that we can muster.
        self._chain = []

        #: List of ELF files which are available for mining gadgets
        self.elfs = elfs

        #: Stack address where the first byte of the ROP chain lies, if known.
        self.base = base

        #: Whether or not the ROP chain directly sets the stack pointer to a value
        #: which is not contiguous
        self.migrated = False

        #: Characters which should not appear in ROP gadget addresses.
        self._badchars = set(badchars)

        self.__load()

    @staticmethod
    @LocalContext
    def from_blob(blob, *a, **kw):
        return ROP(ELF.from_bytes(blob, *a, **kw))

    def setRegisters(self, registers):
        """
        Returns an list of addresses/values which will set the specified register context.

        Arguments:
            registers(dict): Dictionary of ``{register name: value}``

        Returns:
            A list of tuples, ordering the stack.

            Each tuple is in the form of ``(value, name)`` where ``value`` is either a
            gadget address or literal value to go on the stack, and ``name`` is either
            a string name or other item which can be "unresolved".

        Note:
            This is basically an implementation of the Set Cover Problem, which is
            NP-hard.  This means that we will take polynomial time N**2, where N is
            the number of gadgets.  We can reduce runtime by discarding useless and
            inferior gadgets ahead of time.
        """
        if not registers:
            return []

        regset = set(registers)

        bad_instructions = set(('syscall', 'sysenter', 'int 0x80'))
        
        # Collect all gadgets which use these registers
        # Also collect the "best" gadget for each combination of registers
        gadgets = []
        best_gadgets = {}

        for gadget in self.gadgets.values():
            # Do not use gadgets which doesn't end with 'ret'
            if gadget.insns[-1] != 'ret':
                continue
            # Do not use gadgets which contain 'syscall' or 'int'
            if set(gadget.insns) & bad_instructions:
                continue

            touched = tuple(regset & set(gadget.regs))

            if not touched:
                continue

            old = best_gadgets.get(touched, gadget)

            # if we have a new gadget for the touched registers, choose it
            # if the new gadget requires less stack space, choose it
            # if both gadgets require same stack space, choose the one with less instructions
            if (old is gadget) \
              or (old.move > gadget.move) \
              or (old.move == gadget.move and len(old.insns) > len(gadget.insns)):
                best_gadgets[touched] = gadget

        winner = None
        budget = 999999999

        for num_gadgets in range(len(registers)):
            for combo in itertools.combinations(sorted(best_gadgets.values(), key=repr, reverse=True), 1+num_gadgets):
                # Is this better than what we can already do?
                cost = sum((g.move for g in combo))
                if cost > budget:
                    continue

                # Does it hit all of the registers we want?
                coverage = set(sum((g.regs for g in combo), [])) & regset

                if coverage != regset:
                    continue

                # It is better than what we had, and hits all of the registers.
                winner = combo
                budget = cost

        if not winner:
            log.error("Could not satisfy setRegisters(%r)", registers)

        # We have our set of "winner" gadgets, let's build a stack!
        stack = []

        for gadget in winner:
            moved = 8 # Account for the gadget itself
            goodregs = set(gadget.regs) & regset
            name = ",".join(goodregs)
            stack.append((gadget.address, gadget))
            for r in gadget.regs:
                moved += 8
                if r in registers:
                    stack.append((registers[r], r))
                else:
                    stack.append((Padding('<pad %s>' % r), r))

            for slot in range(moved, gadget.move, context.bytes):
                left = gadget.move - slot
                stack.append((Padding('<pad %#x>' % left), 'stack padding'))

        return stack

    def __call__(self, *args, **kwargs):
        """Set the given register(s)' by constructing a rop chain.

        This is a thin wrapper around :meth:`setRegisters` which
        actually executes the rop chain.

        You can call this :class:`ROP` instance and provide keyword arguments,
        or a dictionary.

        Arguments:
            regs(dict): Mapping of registers to values.
                        Can instead provide ``kwargs``.

        >>> context.clear(arch='amd64')
        >>> assembly = 'pop rax; pop rdi; pop rsi; ret; pop rax; ret;'
        >>> e = ELF.from_assembly(assembly)
        >>> r = ROP(e)
        >>> r(rax=0xdead, rdi=0xbeef, rsi=0xcafe)
        >>> print(r.dump())
        0x0000:       0x10000000
        0x0008:           0xdead
        0x0010:           0xbeef
        0x0018:           0xcafe
        >>> r = ROP(e)
        >>> r({'rax': 0xdead, 'rdi': 0xbeef, 'rsi': 0xcafe})
        >>> print(r.dump())
        0x0000:       0x10000000
        0x0008:           0xdead
        0x0010:           0xbeef
        0x0018:           0xcafe
        """
        if len(args) == 1 and isinstance(args[0], dict):
            for value, _ in self.setRegisters(args[0]):
                self.raw(value)
        else:
            self(kwargs)

    def resolve(self, resolvable):
        """Resolves a symbol to an address

        Arguments:
            resolvable(str,int): Thing to convert into an address

        Returns:
            int containing address of 'resolvable', or None
        """
        if isinstance(resolvable, str):
            for elf in self.elfs:
                if resolvable in elf.symbols:
                    return elf.symbols[resolvable]

        if isinstance(resolvable, six.integer_types):
            return resolvable

    def unresolve(self, value):
        """Inverts 'resolve'.  Given an address, it attempts to find a symbol
        for it in the loaded ELF files.  If none is found, it searches all
        known gadgets, and returns the disassembly

        Arguments:
            value(int): Address to look up

        Returns:
            String containing the symbol name for the address, disassembly for a gadget
            (if there's one at that address), or an empty string.
        """
        for elf in self.elfs:
            for name, addr in elf.symbols.items():
                if addr == value:
                    return name

        if value in self.gadgets:
            return '; '.join(self.gadgets[value].insns)
        return ''

    def generatePadding(self, offset, count):
        """
        Generates padding to be inserted into the ROP stack.

        >>> context.clear(arch='i386')
        >>> rop = ROP([])
        >>> val = rop.generatePadding(5,15)
        >>> cyclic_find(val[:4])
        5
        >>> len(val)
        15
        >>> rop.generatePadding(0,0)
        b''

        """

        # Ensure we don't generate a cyclic pattern which contains badchars
        alphabet = b''.join(packing.p8(c) for c in bytearray(string.ascii_lowercase.encode()) if c not in self._badchars)

        if count:
            return cyclic(offset + count, alphabet=alphabet)[-count:]
        return b''

    def describe(self, object):
        """
        Return a description for an object in the ROP stack
        """
        if isinstance(object, enums):
            return str(object)
        if isinstance(object, six.integer_types):
            return self.unresolve(object)
        if isinstance(object, (bytes, six.text_type)):
            return repr(object)
        if isinstance(object, Gadget):
            return '; '.join(object.insns)

    def build(self, base = None, description = None):
        """
        Construct the ROP chain into a list of elements which can be passed
        to :func:`.flat`.

        Arguments:
            base(int):
                The base address to build the rop-chain from. Defaults to
                :attr:`base`.
            description(dict):
                Optional output argument, which will gets a mapping of
                ``address: description`` for each address on the stack,
                starting at ``base``.
        """
        if base is None:
            base = self.base or 0

        stack = DescriptiveStack(base)
        chain = self._chain

        #
        # First pass
        #
        # Get everything onto the stack and save as much descriptive information
        # as possible.
        #
        # The only replacements performed are to add stack adjustment gadgets
        # (to move SP to the next gadget after a Call) and NextGadgetAddress,
        # which can only be calculated in this pass.
        #
        iterable = enumerate(chain)
        for idx, slot in iterable:

            remaining = len(chain) - 1 - idx
            address   = stack.next

            # Integers can just be added.
            # Do our best to find out what the address is.
            if isinstance(slot, six.integer_types):
                stack.describe(self.describe(slot))
                stack.append(slot)


            # Byte blobs can also be added, however they must be
            # broken down into pointer-width blobs.
            elif isinstance(slot, (bytes, six.text_type)):
                stack.describe(self.describe(slot))
                if not isinstance(slot, bytes):
                    slot = slot.encode()

                for chunk in lists.group(context.bytes, slot):
                    stack.append(chunk)

            elif isinstance(slot, srop.SigreturnFrame):
                stack.describe("Sigreturn Frame")

                if slot.sp in (0, None) and self.base:
                    slot.sp = stack.next + len(slot)

                registers = [slot.registers[i] for i in sorted(slot.registers.keys())]
                for register in registers:
                    value       = slot[register]
                    description = self.describe(value)
                    if description:
                        stack.describe('%s = %s' % (register, description))
                    else:
                        stack.describe('%s' % (register))
                    stack.append(value)

            elif isinstance(slot, Call):
                stack.describe(self.describe(slot))

                registers    = slot.register_arguments

                for value, name in self.setRegisters(registers):
                    if name in registers:
                        index = slot.abi.register_arguments.index(name)
                        description = self.describe(value) or repr(value)
                        stack.describe('[arg%d] %s = %s' % (index, name, description))
                    elif isinstance(name, Gadget):
                        stack.describe('; '.join(name.insns))
                    elif isinstance(name, str):
                        stack.describe(name)
                    stack.append(value)

                if address != stack.next:
                    stack.describe(slot.name)

                stack.append(slot.target)

                # For any remaining arguments, put them on the stack
                stackArguments = slot.stack_arguments
                for argument in slot.stack_arguments_before:
                    stack.describe("[dlresolve index]")
                    stack.append(argument)
                nextGadgetAddr = stack.next + (context.bytes * len(stackArguments))

                # Generally, stack-based arguments assume there's a return
                # address on the stack.
                #
                # We need to at least put padding there so that things line up
                # properly, but likely also need to adjust the stack past the
                # arguments.
                if slot.abi.returns:

                    # Save off the address of the next gadget
                    if remaining or stackArguments:
                        nextGadgetAddr = stack.next

                    # If there were arguments on the stack, we need to stick something
                    # in the slot where the return address goes.
                    if len(stackArguments) > 0:
                        if remaining:
                            fix_size  = (1 + len(stackArguments))
                            fix_bytes = fix_size * context.bytes
                            adjust   = self.search(move = fix_bytes)

                            if not adjust:
                                log.error("Could not find gadget to adjust stack by %#x bytes" % fix_bytes)

                            nextGadgetAddr += adjust.move

                            stack.describe('<adjust @%#x> %s' % (nextGadgetAddr, self.describe(adjust)))
                            stack.append(adjust.address)

                            for pad in range(fix_bytes, adjust.move, context.bytes):
                                stackArguments.append(Padding())

                        # We could not find a proper "adjust" gadget, but also didn't need one.
                        else:
                            stack.append(Padding("<return address>"))


                for i, argument in enumerate(stackArguments):

                    if isinstance(argument, NextGadgetAddress):
                        stack.describe("<next gadget>")
                        stack.append(nextGadgetAddr)

                    else:
                        description = self.describe(argument) or 'arg%i' % (i + len(registers))
                        stack.describe(description)
                        stack.append(argument)
            else:
                stack.append(slot)
        #
        # Second pass
        #
        # All of the register-loading, stack arguments, and call addresses
        # are on the stack.  We can now start loading in absolute addresses.
        #
        start = base
        end   = stack.next
        size  = (stack.next - base)
        slot_address = base
        for i, slot in enumerate(stack):
            if isinstance(slot, six.integer_types):
                pass

            elif isinstance(slot, (bytes, six.text_type)):
                pass

            elif isinstance(slot, AppendedArgument):
                stack[i] = stack.next
                stack.extend(slot.resolve(stack.next))

            elif isinstance(slot, CurrentStackPointer):
                stack[i] = slot_address

            elif isinstance(slot, Padding):
                stack[i] = self.generatePadding(i * context.bytes, context.bytes)
                stack.describe(slot.name, slot_address)

            elif isinstance(slot, Gadget):
                stack[i] = slot.address
                stack.describe(self.describe(slot), slot_address)

            # Everything else we can just leave in place.
            # Maybe the user put in something on purpose?
            # Also, it may work in pwnlib.util.packing.flat()
            else:
                pass

            slot_address += _slot_len(slot)

        return stack


    def find_stack_adjustment(self, slots):
        self.search(move=slots * context.bytes)

    def chain(self, base=None):
        """Build the ROP chain
        
        Arguments:
            base(int):
                The base address to build the rop-chain from. Defaults to
                :attr:`base`.

        Returns:
            str containing raw ROP bytes
        """
        return packing.flat(self.build(base=base))

    def dump(self, base=None):
        """Dump the ROP chain in an easy-to-read manner
        
        Arguments:
            base(int):
                The base address to build the rop-chain from. Defaults to
                :attr:`base`.
        """
        return self.build(base=base).dump()

    def regs(self, registers=None, **kw):
        if registers is None:
            registers = {}
        registers.update(kw)



    def call(self, resolvable, arguments = (), abi = None, **kwargs):
        """Add a call to the ROP chain

        Arguments:
            resolvable(str,int): Value which can be looked up via 'resolve',
                or is already an integer.
            arguments(list): List of arguments which can be passed to pack().
                Alternately, if a base address is set, arbitrarily nested
                structures of strings or integers can be provided.
        """
        if self.migrated:
            log.error('Cannot append to a migrated chain')

        # If we can find a function with that name, just call it
        if isinstance(resolvable, str):
            addr = self.resolve(resolvable)
        elif hasattr(resolvable, 'name') and hasattr(resolvable, 'address'):
            addr = resolvable.address
            resolvable = str(resolvable.name)
        else:
            addr = resolvable
            resolvable = ''

        if addr:
            self.raw(Call(resolvable, addr, arguments, abi))

        # Otherwise, if it is a syscall we might be able to call it
        elif not self._srop_call(resolvable, arguments):
            log.error('Could not resolve %r.' % resolvable)



    def _srop_call(self, resolvable, arguments):
        # Check that the call is a valid syscall
        resolvable    = 'SYS_' + resolvable.lower()
        syscall_number = getattr(constants, resolvable, None)
        if syscall_number is None:
            return False

        log.info_once("Using sigreturn for %r" % resolvable)

        # Find an int 0x80 or similar instruction we can use
        syscall_gadget       = None
        syscall_instructions = srop.syscall_instructions[context.arch]

        for instruction in syscall_instructions:
            syscall_gadget = self.find_gadget([instruction])
            if syscall_gadget:
                break
        else:
            log.error("Could not find any instructions in %r" % syscall_instructions)

        # Generate the SROP frame which would invoke the syscall
        with context.local(arch=self.elfs[0].arch):
            frame         = srop.SigreturnFrame()
            frame.pc      = syscall_gadget
            frame.syscall = syscall_number

            try:
                SYS_sigreturn  = constants.SYS_sigreturn
            except AttributeError:
                SYS_sigreturn  = constants.SYS_rt_sigreturn

            for register, value in zip(frame.arguments, arguments):
                if not isinstance(value, six.integer_types + (Unresolved,)):
                    frame[register] = AppendedArgument(value)
                else:
                    frame[register] = value

        # Set up a call frame which will set EAX and invoke the syscall
        call = Call('SYS_sigreturn',
                    syscall_gadget,
                    [SYS_sigreturn],
                    abi.ABI.sigreturn())

        self.raw(call)
        self.raw(frame)


        # We do not expect to ever recover after the syscall, as it would
        # require something like 'int 0x80; ret' which does not ever occur
        # in the wild.
        self.migrated = True

        return True

    def find_gadget(self, instructions):
        """
        Returns a gadget with the exact sequence of instructions specified
        in the ``instructions`` argument.
        """
        n = len(instructions)
        for gadget in self.gadgets.values():
            if tuple(gadget.insns)[:n] == tuple(instructions):
                return gadget


    def raw(self, value):
        """Adds a raw integer or string to the ROP chain.

        If your architecture requires aligned values, then make
        sure that any given string is aligned!

        Arguments:
            data(int/str): The raw value to put onto the rop chain.

        >>> context.clear(arch='i386')
        >>> rop = ROP([])
        >>> rop.raw('AAAAAAAA')
        >>> rop.raw('BBBBBBBB')
        >>> rop.raw('CCCCCCCC')
        >>> print(rop.dump())
        0x0000:          b'AAAA' 'AAAAAAAA'
        0x0004:          b'AAAA'
        0x0008:          b'BBBB' 'BBBBBBBB'
        0x000c:          b'BBBB'
        0x0010:          b'CCCC' 'CCCCCCCC'
        0x0014:          b'CCCC'
        """
        if self.migrated:
            log.error('Cannot append to a migrated chain')
        self._chain.append(value)

    def migrate(self, next_base):
        """Explicitly set $sp, by using a ``leave; ret`` gadget"""
        if isinstance(next_base, ROP):
            next_base = next_base.base
        pop_sp = self.rsp or self.esp
        pop_bp = self.rbp or self.ebp
        leave  = self.leave
        if pop_sp and len(pop_sp.regs) == 1:
            self.raw(pop_sp)
            self.raw(next_base)
        elif pop_bp and leave and len(pop_bp.regs) == 1:
            self.raw(pop_bp)
            self.raw(next_base - context.bytes)
            self.raw(leave)
        else:
            log.error('Cannot find the gadgets to migrate')
        self.migrated = True

    def __bytes__(self):
        """Returns: Raw bytes of the ROP chain"""
        return self.chain()

    def __get_cachefile_name(self, files):
        """Given an ELF or list of ELF objects, return a cache file for the set of files"""
        cachedir = os.path.join(context.cache_dir, 'rop-cache')
        if not os.path.exists(cachedir):
            os.mkdir(cachedir)

        if isinstance(files, ELF):
            files = [files]

        sha256 = hashlib.sha256()
        for elf_data in sorted(elf.get_data() for elf in files):
            sha256.update(elf_data)

        return os.path.join(cachedir, sha256.hexdigest())

    @staticmethod
    def clear_cache():
        """Clears the ROP gadget cache"""
        cachedir = os.path.join(context.cache_dir, 'rop-cache')
        shutil.rmtree(cachedir)

    def __cache_load(self, elf):
        filename = self.__get_cachefile_name(elf)
        if not os.path.exists(filename):
            return None
        gadgets = eval(open(filename).read())
        gadgets = {k - elf.load_addr + elf.address:v for k, v in gadgets.items()}
        log.info_once('Loaded %s cached gadgets for %r', len(gadgets), elf.file.name)
        return gadgets

    def __cache_save(self, elf, data):
        data = {k + elf.load_addr - elf.address:v for k, v in data.items()}
        open(self.__get_cachefile_name(elf), 'w+').write(repr(data))

    def __load(self):
        """Load all ROP gadgets for the selected ELF files"""
        #
        # We accept only instructions that look like these.
        #
        # - leave
        # - pop reg
        # - add $sp, <hexadecimal value>
        # - ret
        #
        # Currently, ROPgadget does not detect multi-byte "C2" ret.
        # https://github.com/JonathanSalwan/ROPgadget/issues/53
        #

        pop   = re.compile(r'^pop (.{3})')
        add   = re.compile(r'^add [er]sp, ((?:0[xX])?[0-9a-fA-F]+)$')
        ret   = re.compile(r'^ret$')
        leave = re.compile(r'^leave$')
        int80 = re.compile(r'int +0x80')
        syscall = re.compile(r'^syscall$')
        sysenter = re.compile(r'^sysenter$')

        #
        # Validation routine
        #
        # >>> valid('pop eax')
        # True
        # >>> valid('add rax, 0x24')
        # False
        # >>> valid('add esp, 0x24')
        # True
        # >>> valid('add esp, esi')
        # False
        #
        valid = lambda insn: any(map(lambda pattern: pattern.match(insn), [pop,add,ret,leave,int80,syscall,sysenter]))

        #
        # Currently, ropgadget.args.Args() doesn't take any arguments, and pulls
        # only from sys.argv.  Preserve it through this call.  We also
        # monkey-patch sys.stdout to suppress output from ropgadget.
        #
        argv = sys.argv
        stdout = sys.stdout

        class Wrapper:

            def __init__(self, fd):
                self._fd = fd

            def write(self, s):
                pass

            def __getattr__(self, k):
                return self._fd.__getattribute__(k)

        gadgets = {}
        for elf in self.elfs:
            cache = self.__cache_load(elf)
            if cache:
                gadgets.update(cache)
                continue
            log.info_once('Loading gadgets for %r' % elf.path)
            try:
                sys.stdout = Wrapper(sys.stdout)
                import ropgadget
                sys.argv = ['ropgadget', '--binary', elf.path, '--only', 'sysenter|syscall|int|add|pop|leave|ret', '--nojop', '--multibr']
                args = ropgadget.args.Args().getArgs()
                core = ropgadget.core.Core(args)
                core.do_binary(elf.path)
                core.do_load(0)
            finally:
                sys.argv = argv
                sys.stdout = stdout

            elf_gadgets = {}
            for gadget in core._Core__gadgets:
                address = gadget['vaddr'] - elf.load_addr + elf.address
                insns = [ g.strip() for g in gadget['gadget'].split(';') ]
                if all(map(valid, insns)):
                    elf_gadgets[address] = insns

            self.__cache_save(elf, elf_gadgets)
            gadgets.update(elf_gadgets)

        #
        # For each gadget we decided to keep, find out how much it moves the stack,
        # and log which registers it modifies.
        #
        self.gadgets = {}
        self.pivots = {}
        frame_regs = {
            4: ['ebp', 'esp'],
            8: ['rbp', 'rsp']
        }[context.bytes]

        for addr, insns in gadgets.items():

            # Filter out gadgets by address against badchars
            if set(pack(addr)) & self._badchars:
                continue

            sp_move = 0
            regs = []
            for insn in insns:
                if pop.match(insn):
                    regs.append(pop.match(insn).group(1))
                    sp_move += context.bytes
                elif add.match(insn):
                    sp_move += int(add.match(insn).group(1), 16)
                elif ret.match(insn):
                    sp_move += context.bytes
                elif leave.match(insn):
                    #
                    # HACK: Since this modifies ESP directly, this should
                    #       never be returned as a 'normal' ROP gadget that
                    #       simply 'increments' the stack.
                    #
                    #       As such, the 'move' is set to a very large value,
                    #       to prevent .search() from returning it unless $sp
                    #       is specified as a register.
                    #
                    sp_move += 9999999999
                    regs += frame_regs

            # Permit duplicates, because blacklisting bytes in the gadget
            # addresses may result in us needing the dupes.
            self.gadgets[addr] = Gadget(addr, insns, regs, sp_move)

            # Don't use 'pop esp' for pivots
            if not set(['rsp', 'esp']) & set(regs):
                self.pivots[sp_move] = addr

        leave = self.search(regs=frame_regs, order='regs')
        if leave and leave.regs != frame_regs:
            leave = None
        self.leave = leave

    def __repr__(self):
        return 'ROP(%r)' % self.elfs

    def search_iter(self, move=None, regs=None):
        """
        Iterate through all gadgets which move the stack pointer by
        *at least* ``move`` bytes, and which allow you to set all
        registers in ``regs``.
        """
        move = move or 0
        regs = set(regs or ())

        for addr, gadget in self.gadgets.items():
            addr_bytes = set(pack(gadget.address))
            if addr_bytes & self._badchars:     continue
            if gadget.insns[-1] != 'ret':        continue
            if gadget.move < move:               continue
            if not (regs <= set(gadget.regs)):   continue
            yield gadget

    def search(self, move = 0, regs = None, order = 'size'):
        """Search for a gadget which matches the specified criteria.

        Arguments:
            move(int): Minimum number of bytes by which the stack
                pointer is adjusted.
            regs(list): Minimum list of registers which are popped off the
                stack.
            order(str): Either the string 'size' or 'regs'. Decides how to
                order multiple gadgets the fulfill the requirements.

        The search will try to minimize the number of bytes popped more than
        requested, the number of registers touched besides the requested and
        the address.

        If ``order == 'size'``, then gadgets are compared lexicographically
        by ``(total_moves, total_regs, addr)``, otherwise by ``(total_regs, total_moves, addr)``.

        Returns:
            A :class:`.Gadget` object
        """
        matches = self.search_iter(move, regs)
        if matches is None:
            return None

        # Search for an exact match, save the closest match
        key = {
            'size': lambda g: (g.move, len(g.regs), g.address),
            'regs': lambda g: (len(g.regs), g.move, g.address)
        }[order]

        try:
            result = min(matches, key=key)
        except ValueError:
            return None

        # Check for magic 9999999... value used by 'leave; ret'
        if move and result.move == 9999999999:
            return None

        return result

    def ret2dlresolve(self, dlresolve):
        elf = next(elf for elf in self.elfs if elf.get_section_by_name(".plt"))
        elf_base = elf.address if elf.pie else 0
        plt_init = elf.get_section_by_name(".plt").header.sh_addr + elf_base
        log.debug("PLT_INIT: %#x", plt_init)

        reloc_index = dlresolve.reloc_index
        real_args = dlresolve.real_args
        call = Call("[plt_init] " + dlresolve.symbol.decode(),
                    plt_init,
                    dlresolve.real_args,
                    before=[reloc_index])
        self.raw(call)

    def __getattr__(self, attr):
        """Helper to make finding ROP gadgets easier.

        Also provides a shorthand for ``.call()``:
            ``rop.function(args)`` is equivalent to ``rop.call(function, args)``

        >>> context.clear(arch='i386')
        >>> elf=ELF(which('bash'))
        >>> rop=ROP([elf])
        >>> rop.rdi     == rop.search(regs=['rdi'], order = 'regs')
        True
        >>> rop.r13_r14_r15_rbp == rop.search(regs=['r13','r14','r15','rbp'], order = 'regs')
        True
        >>> rop.ret_8   == rop.search(move=8)
        True
        >>> rop.ret is not None
        True
        >>> with context.local(arch='amd64', bits='64'):
        ...     r = ROP(ELF.from_assembly('syscall; ret'))
        >>> r.syscall is not None
        True
        """
        gadget = collections.namedtuple('gadget', ['address', 'details'])

        if attr in self.__dict__ \
        or attr in self.BAD_ATTRS \
        or attr.startswith('_'):
            raise AttributeError('ROP instance has no attribute %r' % attr)

        #
        # Check for 'ret' or 'ret_X'
        #
        if attr.startswith('ret'):
            count = context.bytes
            if '_' in attr:
                count = int(attr.split('_')[1])
            return self.search(move=count)

        #
        # Check for 'jmp_esp'('i386') or 'jmp_rsp'('amd64')
        #
        if attr == 'jmp_esp' and context.arch == 'i386' \
        or attr == 'jmp_rsp' and context.arch == 'amd64':
            jmp_sp = {'i386': 'jmp esp',
                      'amd64': 'jmp rsp'
                     }[context.arch]

            insn_asm = b'\xff\xe4'

            for elf in self.elfs:
                for addr in elf.search(insn_asm, executable = True):
                    if set(pack(addr)) & self._badchars:
                        continue

                    return Gadget(addr, [jmp_sp], [], context.bytes)
            return None

        if attr in ('int80', 'syscall', 'sysenter'):
            mapping = {'int80': 'int 0x80',
             'syscall': 'syscall',
             'sysenter': 'sysenter'}
            for each in self.gadgets:
                if self.gadgets[each]['insns'][0] == mapping[attr]:
                    return gadget(each, self.gadgets[each])
            return None

        #
        # Check for a '_'-delimited list of registers
        #
        if all(map(lambda x: x[-2:] in self.X86_SUFFIXES, attr.split('_'))):
            return self.search(regs=attr.split('_'), order='regs')

        #
        # Otherwise, assume it's a rop.call() shorthand
        #
        def call(*args):
            return self.call(attr, args)

        return call

    def __setattr__(self, attr, value):
        """Helper for setting registers.

        This convenience feature allows one to set the values of registers
        with simple python assignment syntax.

        Warning:
            Only one register is set at a time (one per rop chain).
            This may lead to some previously set to registers be overwritten!

        Note:
            If you would like to set multiple registers in as few rop chains
            as possible, see :meth:`__call__`.

        >>> context.clear(arch='amd64')
        >>> assembly = 'pop rax; pop rdi; pop rsi; ret; pop rax; ret;'
        >>> e = ELF.from_assembly(assembly)
        >>> r = ROP(e)
        >>> r.rax = 0xdead
        >>> r.rdi = 0xbeef
        >>> r.rsi = 0xcafe
        >>> print(r.dump())
        0x0000:       0x10000004 pop rax; ret
        0x0008:           0xdead
        0x0010:       0x10000001 pop rdi; pop rsi; ret
        0x0018:           0xbeef
        0x0020:      b'iaaajaaa' <pad rsi>
        0x0028:       0x10000002 pop rsi; ret
        0x0030:           0xcafe
        """
        if attr in self.BAD_ATTRS:
            raise AttributeError('ROP instance has no attribute %r' % attr)

        if attr[-2:] in self.X86_SUFFIXES:  # handle setting registers
            self({attr: value})

        # Otherwise, perform usual setting
        self.__dict__[attr] = value
