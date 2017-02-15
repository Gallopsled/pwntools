r"""
Return Oriented Programming

Manual ROP
-------------------

The ROP tool can be used to build stacks pretty trivially.
Let's create a fake binary which has some symbols which might
have been useful.

    >>> context.clear(arch='i386')
    >>> binary = ELF.from_assembly('add esp, 0x10; ret')
    >>> binary.symbols = {'read': 0xdeadbeef, 'write': 0xdecafbad, 'exit': 0xfeedface}

Creating a ROP object which looks up symbols in the binary is
pretty straightforward.

    >>> rop = ROP(binary)

With the ROP object, you can manually add stack frames.

    >>> rop.raw(0)
    >>> rop.raw(unpack('abcd'))
    >>> rop.raw(2)

Inspecting the ROP stack is easy, and laid out in an easy-to-read
manner.

    >>> print rop.dump()
    0x0000:              0x0
    0x0004:       0x64636261
    0x0008:              0x2

The ROP module is also aware of how to make function calls with
standard Linux ABIs.

    >>> rop.call('read', [4,5,6])
    >>> print rop.dump()
    0x0000:              0x0
    0x0004:       0x64636261
    0x0008:              0x2
    0x000c:       0xdeadbeef read(4, 5, 6)
    0x0010:           'eaaa' <pad>
    0x0014:              0x4 arg0
    0x0018:              0x5 arg1
    0x001c:              0x6 arg2

You can also use a shorthand to invoke calls.
The stack is automatically adjusted for the next frame

    >>> rop.write(7,8,9)
    >>> rop.exit()
    >>> print rop.dump()
    0x0000:              0x0
    0x0004:       0x64636261
    0x0008:              0x2
    0x000c:       0xdeadbeef read(4, 5, 6)
    0x0010:       0x10000000 <adjust: add esp, 0x10; ret>
    0x0014:              0x4 arg0
    0x0018:              0x5 arg1
    0x001c:              0x6 arg2
    0x0020:           'iaaa' <pad>
    0x0024:       0xdecafbad write(7, 8, 9)
    0x0028:       0x10000000 <adjust: add esp, 0x10; ret>
    0x002c:              0x7 arg0
    0x0030:              0x8 arg1
    0x0034:              0x9 arg2
    0x0038:           'oaaa' <pad>
    0x003c:       0xfeedface exit()
    0x0040:           'qaaa' <pad>

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
    >>> print rop.dump()
    0x0000:       0x10000012 write(STDOUT_FILENO, 268435494, 8)
    0x0004:       0x1000000e <adjust: add esp, 0x10; ret>
    0x0008:              0x1 arg0
    0x000c:       0x10000026 flag
    0x0010:              0x8 arg2
    0x0014:           'faaa' <pad>
    0x0018:       0x1000002f exit()
    0x001c:           'haaa' <pad>

The raw data from the ROP stack is available via `str`.

    >>> raw_rop = str(rop)
    >>> print enhex(raw_rop)
    120000100e000010010000002600001008000000666161612f00001068616161

Let's try it out!

    >>> p = process(binary.path)
    >>> p.send(raw_rop)
    >>> print p.recvall(timeout=5)
    The flag

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

    >>> print rop.dump()
    0x0000:       0x1000000e pop eax; ret
    0x0004:             0x77
    0x0008:       0x1000000b int 0x80
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
    0x0038:              0xb eax
    0x003c:              0x0 trapno
    0x0040:              0x0 err
    0x0044:       0x1000000b int 0x80
    0x0048:             0x23 cs
    0x004c:              0x0 eflags
    0x0050:              0x0 esp_at_signal
    0x0054:             0x2b ss
    0x0058:              0x0 fpstate

Let's try it out!

    >>> p = process(binary.path)
    >>> p.send(str(rop))
    >>> time.sleep(1)
    >>> p.sendline('echo hello; exit')
    >>> p.recvline()
    'hello\n'
"""
from __future__ import absolute_import

import collections
import copy
import hashlib
import os
import re
import sys
import tempfile

from pwnlib import abi
from pwnlib import constants
from pwnlib.context import LocalContext
from pwnlib.context import context
from pwnlib.elf import ELF
from pwnlib.log import getLogger
from pwnlib.rop import srop
from pwnlib.rop.call import AppendedArgument
from pwnlib.rop.call import Call
from pwnlib.rop.call import CurrentStackPointer
from pwnlib.rop.call import NextGadgetAddress
from pwnlib.rop.call import StackAdjustment
from pwnlib.rop.gadgets import Gadget
from pwnlib.util import cyclic
from pwnlib.util import lists
from pwnlib.util import packing
from pwnlib.util.packing import *

log = getLogger(__name__)
__all__ = ['ROP']


class Padding(object):
    """
    Placeholder for exactly one pointer-width of padding.
    """

class DescriptiveStack(list):
    """
    List of resolved ROP gadgets that correspond to the ROP calls that
    the user has specified.  Also includes
    """

    #: Base address
    address = 0

    #: Dictionary of ``{address: [list of descriptions]}``
    descriptions = {}

    def __init__(self, address):
        self.descriptions = collections.defaultdict(lambda: [])
        self.address      = address or 0

    @property
    def next(self):
        return self.address + len(self) * context.bytes

    def describe(self, text, address = None):
        if address is None:
            address = self.next
        self.descriptions[address] = text

    def dump(self):
        rv = []
        for i, data in enumerate(self):
            addr = self.address + i * context.bytes
            off = None
            line = '0x%04x:' % addr
            if isinstance(data, str):
                line += ' %16r' % data
            elif isinstance(data, (int,long)):
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

        return '\n'.join(rv)


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
       str(rop)
       # '\xfc\x82\x04\x08\xef\xbe\xad\xde\x00\x00\x00\x00\xa8\x96\x04\x08'

    >>> context.clear(arch = "i386", kernel = 'amd64')
    >>> assembly = 'int 0x80; ret; add esp, 0x10; ret; pop eax; ret'
    >>> e = ELF.from_assembly(assembly)
    >>> e.symbols['funcname'] = e.address + 0x1234
    >>> r = ROP(e)
    >>> r.funcname(1, 2)
    >>> r.funcname(3)
    >>> r.execve(4, 5, 6)
    >>> print r.dump()
    0x0000:       0x10001234 funcname(1, 2)
    0x0004:       0x10000003 <adjust: add esp, 0x10; ret>
    0x0008:              0x1 arg0
    0x000c:              0x2 arg1
    0x0010:           'eaaa' <pad>
    0x0014:           'faaa' <pad>
    0x0018:       0x10001234 funcname(3)
    0x001c:       0x10000007 <adjust: pop eax; ret>
    0x0020:              0x3 arg0
    0x0024:       0x10000007 pop eax; ret
    0x0028:             0x77
    0x002c:       0x10000000 int 0x80
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
    0x005c:              0xb eax
    0x0060:              0x0 trapno
    0x0064:              0x0 err
    0x0068:       0x10000000 int 0x80
    0x006c:             0x23 cs
    0x0070:              0x0 eflags
    0x0074:              0x0 esp_at_signal
    0x0078:             0x2b ss
    0x007c:              0x0 fpstate

    >>> r = ROP(e, 0x8048000)
    >>> r.funcname(1, 2)
    >>> r.funcname(3)
    >>> r.execve(4, 5, 6)
    >>> print r.dump()
    0x8048000:       0x10001234 funcname(1, 2)
    0x8048004:       0x10000003 <adjust: add esp, 0x10; ret>
    0x8048008:              0x1 arg0
    0x804800c:              0x2 arg1
    0x8048010:           'eaaa' <pad>
    0x8048014:           'faaa' <pad>
    0x8048018:       0x10001234 funcname(3)
    0x804801c:       0x10000007 <adjust: pop eax; ret>
    0x8048020:              0x3 arg0
    0x8048024:       0x10000007 pop eax; ret
    0x8048028:             0x77
    0x804802c:       0x10000000 int 0x80
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
    0x804805c:              0xb eax
    0x8048060:              0x0 trapno
    0x8048064:              0x0 err
    0x8048068:       0x10000000 int 0x80
    0x804806c:             0x23 cs
    0x8048070:              0x0 eflags
    0x8048074:              0x0 esp_at_signal
    0x8048078:             0x2b ss
    0x804807c:              0x0 fpstate
    """
    #: List of individual ROP gadgets, ROP calls, SROP frames, etc.
    #: This is intended to be the highest-level abstraction that we can muster.
    _chain = []

    #: List of ELF files which are available for mining gadgets
    elfs = []

    #: Stack address where the first byte of the ROP chain lies, if known.
    base = 0

    #: Whether or not the ROP chain directly sets the stack pointer to a value
    #: which is not contiguous
    migrated = False

    def __init__(self, elfs, base = None, **kwargs):
        """
        Arguments:
            elfs(list): List of :class:`.ELF` objects for mining
        """
        import ropgadget

        # Permit singular ROP(elf) vs ROP([elf])
        if isinstance(elfs, ELF):
            elfs = [elfs]
        elif isinstance(elfs, (str, unicode)):
            elfs = [ELF(elfs)]
        self.elfs = elfs
        self._chain = []
        self.base = base
        self.migrated = False
        self.__load()

    @staticmethod
    @LocalContext
    def from_blob(blob, *a, **kw):
        return ROP(ELF.from_bytes(blob, *a, **kw))

    def setRegisters(self, registers):
        """
        Returns an OrderedDict of addresses/values which will set the specified
        register context.

        Arguments:
            registers(dict): Dictionary of ``{register name: value}``

        Returns:
            An OrderedDict of ``{register: sequence of gadgets, values, etc.}``.
        """
        reg_order = collections.OrderedDict()

        for reg, value in registers.items():
            gadget = self.find_gadget(['pop ' + reg, 'ret'])
            if not gadget:
                log.error("can't set %r" % reg)
            reg_order[reg] = [gadget, value]

        return reg_order

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

        if isinstance(resolvable, (int, long)):
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

        >>> rop = ROP([])
        >>> val = rop.generatePadding(5,15)
        >>> cyclic_find(val[:4])
        5
        >>> len(val)
        15
        >>> rop.generatePadding(0,0)
        ''

        """
        if count:
            return cyclic.cyclic(offset + count)[-count:]
        return ''

    def describe(self, object):
        """
        Return a description for an object in the ROP stack
        """
        if isinstance(object, (int, long)):
            return self.unresolve(object)
        if isinstance(object, str):
            return repr(object)
        if isinstance(object, Call):
            return str(object)
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
            if isinstance(slot, (int, long)):
                stack.describe(self.describe(slot))
                stack.append(slot)


            # Byte blobs can also be added, however they must be
            # broken down into pointer-width blobs.
            elif isinstance(slot, (str, unicode)):
                stack.describe(self.describe(slot))
                slot += self.generatePadding(stack.next, len(slot) % context.bytes)

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

                registers    = dict(zip(slot.abi.register_arguments, slot.args))
                setRegisters = self.setRegisters(registers)

                for register, gadgets in setRegisters.items():
                    value       = registers[register]
                    description = self.describe(value) or 'arg%i' % slot.args.index(value)
                    stack.describe('set %s = %s' % (register, description))
                    stack.extend(gadgets)

                if address != stack.next:
                    stack.describe(slot.name)

                stack.append(slot.target)

                # For any remaining arguments, put them on the stack
                stackArguments = slot.args[len(slot.abi.register_arguments):]
                nextGadgetAddr = stack.next + (context.bytes * len(stackArguments))

                # Generally, stack-based arguments assume there's a return
                # address on the stack.
                #
                # We need to at least put padding there so that things line up
                # properly, but likely also need to adjust the stack past the
                # arguments.
                if slot.abi.returns:
                    if remaining:
                        fix_size  = (1 + len(stackArguments))
                        fix_bytes = fix_size * context.bytes
                        adjust   = self.search(move = fix_bytes)

                        if not adjust:
                            log.error("Could not find gadget to adjust stack by %#x bytes" % fix_bytes)

                        nextGadgetAddr = stack.next + adjust.move

                        stack.describe('<adjust: %s>' % self.describe(adjust))
                        stack.append(adjust.address)

                        for pad in range(fix_bytes, adjust.move, context.bytes):
                            stackArguments.append(Padding())
                    else:
                        stack.describe('<pad>')
                        stack.append(Padding())


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
        for i, slot in enumerate(stack):
            slot_address = stack.address + (i * context.bytes)
            if isinstance(slot, (int, long)):
                pass

            elif isinstance(slot, (str, unicode)):
                pass

            elif isinstance(slot, AppendedArgument):
                stack[i] = stack.next
                stack.extend(slot.resolve(stack.next))

            elif isinstance(slot, CurrentStackPointer):
                stack[i] = slot_address

            elif isinstance(slot, Padding):
                stack[i] = self.generatePadding(i * context.bytes, context.bytes)
                stack.describe('<pad>', slot_address)

            elif isinstance(slot, Gadget):
                stack[i] = slot.address
                stack.describe(self.describe(slot), slot_address)

            # Everything else we can just leave in place.
            # Maybe the user put in something on purpose?
            # Also, it may work in pwnlib.util.packing.flat()
            else:
                pass

        return stack


    def find_stack_adjustment(self, slots):
        self.search(move=slots * context.arch)

    def chain(self):
        """Build the ROP chain

        Returns:
            str containing raw ROP bytes
        """
        return packing.flat(self.build())

    def dump(self):
        """Dump the ROP chain in an easy-to-read manner"""
        return self.build().dump()

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

        >>> rop = ROP([])
        >>> rop.raw('AAAAAAAA')
        >>> rop.raw('BBBBBBBB')
        >>> rop.raw('CCCCCCCC')
        >>> print rop.dump()
        0x0000:           'AAAA' 'AAAAAAAA'
        0x0004:           'AAAA'
        0x0008:           'BBBB' 'BBBBBBBB'
        0x000c:           'BBBB'
        0x0010:           'CCCC' 'CCCCCCCC'
        0x0014:           'CCCC'
        """
        if self.migrated:
            log.error('Cannot append to a migrated chain')
        self._chain.append(value)

    def migrate(self, next_base):
        """Explicitly set $sp, by using a ``leave; ret`` gadget"""
        if isinstance(next_base, ROP):
            next_base = self.base
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

    def __str__(self):
        """Returns: Raw bytes of the ROP chain"""
        return self.chain()

    def __get_cachefile_name(self, elf):
        basename = os.path.basename(elf.file.name)
        sha256 = hashlib.sha256(elf.get_data()).hexdigest()
        cachedir = os.path.join(tempfile.gettempdir(), 'pwntools-rop-cache')
        if not os.path.exists(cachedir):
            os.mkdir(cachedir)
        return os.path.join(cachedir, sha256)

    def __cache_load(self, elf):
        filename = self.__get_cachefile_name(elf)
        if not os.path.exists(filename):
            return None
        log.info_once('Loaded cached gadgets for %r' % elf.file.name)
        gadgets = eval(file(filename).read())
        gadgets = {k - elf.load_addr + elf.address:v for k, v in gadgets.items()}
        return gadgets

    def __cache_save(self, elf, data):
        data = {k + elf.load_addr - elf.address:v for k, v in data.items()}
        file(self.__get_cachefile_name(elf), 'w+').write(repr(data))

    def __load(self):
        """Load all ROP gadgets for the selected ELF files"""
        #
        # We accept only instructions that look like these.
        #
        # - leave
        # - pop reg
        # - add $sp, value
        # - ret
        #
        # Currently, ROPgadget does not detect multi-byte "C2" ret.
        # https://github.com/JonathanSalwan/ROPgadget/issues/53
        #

        pop   = re.compile(r'^pop (.{3})')
        add   = re.compile(r'^add .sp, (\S+)$')
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
                sys.argv = ['ropgadget', '--binary', elf.path, '--only', 'sysenter|syscall|int|add|pop|leave|ret', '--nojop']
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
            if gadget.move < move:          continue
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

    def __getattr__(self, attr):
        """Helper to make finding ROP gadets easier.

        Also provides a shorthand for ``.call()``:
            ``rop.function(args)`` is equivalent to ``rop.call(function, args)``

        >>> elf=ELF(which('bash'))
        >>> rop=ROP([elf])
        >>> rop.rdi     == rop.search(regs=['rdi'], order = 'regs')
        True
        >>> rop.r13_r14_r15_rbp == rop.search(regs=['r13','r14','r15','rbp'], order = 'regs')
        True
        >>> rop.ret_8   == rop.search(move=8)
        True
        >>> rop.ret     != None
        True
        """
        gadget = collections.namedtuple('gadget', ['address', 'details'])
        bad_attrs = [
            'trait_names',          # ipython tab-complete
            'download',             # frequent typo
            'upload',               # frequent typo
        ]

        if attr in self.__dict__ \
        or attr in bad_attrs \
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

        if attr in ('int80', 'syscall', 'sysenter'):
            mapping = {'int80': 'int 0x80',
             'syscall': 'syscall',
             'sysenter': 'sysenter'}
            for each in self.gadgets:
                if self.gadgets[each]['insns'] == [mapping[attr]]:
                    return gadget(each, self.gadgets[each])
            return None

        #
        # Check for a '_'-delimited list of registers
        #
        x86_suffixes = ['ax', 'bx', 'cx', 'dx', 'bp', 'sp', 'di', 'si',
                        'r8', 'r9', '10', '11', '12', '13', '14', '15']

        if all(map(lambda x: x[-2:] in x86_suffixes, attr.split('_'))):
            return self.search(regs=attr.split('_'), order='regs')

        #
        # Otherwise, assume it's a rop.call() shorthand
        #
        def call(*args):
            return self.call(attr, args)

        return call
