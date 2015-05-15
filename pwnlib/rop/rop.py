# -*- coding: utf-8 -*-
"""Return Oriented Programming
"""
import collections
import copy
import hashlib
import os
import re
import sys
import tempfile

from .. import constants

from ..context import context
from ..elf import ELF
from ..log import getLogger
from ..util import cyclic
from ..util import packing
from ..util.packing import *
from . import srop
from .call import Call
from .gadgets import Gadget

log = getLogger(__name__)
__all__ = ['ROP']


class Padding(object):
    """
    Placeholder for padding.
    """
    size = 0

    def __init__(self, size = None):
        if size is None:
            size = context.bytes
        self.size = size


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
        self.address = address

    @property
    def next(self):
        return self.address + len(self) * context.bytes

    def describe(self, text):
        self.descriptions[self.next] = text

    def dump(self):
        rv = []
        for i, data in self:
            addr = self.address + i * context.bytes
            off = None
            line = '0x%04x:' % addr
            if isinstance(data, str):
                line += ' %16r' % data
            elif isinstance(data, int):
                line += ' %#16x'
                if self.address < data < self.next:
                    off = data - addr
            else:
                log.error("Don't know how to dump %r" % data)
            desc = self.descriptions.get(addr, '')
            if desc:
                line += ' %s'
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

    >>> context.arch = "i386"
    >>> write('/tmp/rop_elf_x86', make_elf(asm('int 0x80; ret; add esp, 0x10; ret; pop eax; ret')))
    >>> e = ELF('/tmp/rop_elf_x86')
    >>> e.symbols['funcname'] = e.address + 0x1234
    >>> r = ROP(e)
    >>> r.funcname(1, 2)
    >>> r.funcname(3)
    >>> r.execve(4, 5, 6)
    >>> print r.dump()
    0x0000:        0x8049288 (funcname)
    0x0004:        0x8048057 (add esp, 0x10; ret)
    0x0008:              0x1
    0x000c:              0x2
    0x0010:           '$$$$'
    0x0014:           '$$$$'
    0x0018:        0x8049288 (funcname)
    0x001c:        0x804805b (pop eax; ret)
    0x0020:              0x3
    0x0024:        0x804805b (pop eax; ret)
    0x0028:             0x77
    0x002c:        0x8048054 (int 0x80)
    0x0030:              0x0 (gs)
    0x0034:              0x0 (fs)
    0x0038:              0x0 (es)
    0x003c:              0x0 (ds)
    0x0040:              0x0 (edi)
    0x0044:              0x0 (esi)
    0x0048:              0x0 (ebp)
    0x004c:              0x0 (esp)
    0x0050:              0x4 (ebx)
    0x0054:              0x6 (edx)
    0x0058:              0x5 (ecx)
    0x005c:              0xb (eax)
    0x0060:              0x0 (trapno)
    0x0064:              0x0 (err)
    0x0068:        0x8048054 (eip)
    0x006c:             0x73 (cs)
    0x0070:              0x0 (eflags)
    0x0074:              0x0 (esp_at_signal)
    0x0078:             0x7b (ss)
    0x007c:              0x0 (fpstate)

    >>> r = ROP(e, 0x8048000)
    >>> r.funcname(1, 2)
    >>> r.funcname(3)
    >>> r.execve(4, 5, 6)
    >>> print r.dump()
    0x8048000:        0x8049288 (funcname)
    0x8048004:        0x8048057 (add esp, 0x10; ret)
    0x8048008:              0x1
    0x804800c:              0x2
    0x8048010:           '$$$$'
    0x8048014:           '$$$$'
    0x8048018:        0x8049288 (funcname)
    0x804801c:        0x804805b (pop eax; ret)
    0x8048020:              0x3
    0x8048024:        0x804805b (pop eax; ret)
    0x8048028:             0x77
    0x804802c:        0x8048054 (int 0x80)
    0x8048030:              0x0 (gs)
    0x8048034:              0x0 (fs)
    0x8048038:              0x0 (es)
    0x804803c:              0x0 (ds)
    0x8048040:              0x0 (edi)
    0x8048044:              0x0 (esi)
    0x8048048:              0x0 (ebp)
    0x804804c:        0x8048080 (esp)
    0x8048050:              0x4 (ebx)
    0x8048054:              0x6 (edx)
    0x8048058:              0x5 (ecx)
    0x804805c:              0xb (eax)
    0x8048060:              0x0 (trapno)
    0x8048064:              0x0 (err)
    0x8048068:        0x8048054 (eip)
    0x804806c:             0x73 (cs)
    0x8048070:              0x0 (eflags)
    0x8048074:              0x0 (esp_at_signal)
    0x8048078:             0x7b (ss)
    0x804807c:              0x0 (fpstate)
    """
    #: List of individual ROP gadgets, ROP calls, SROP frames, etc.
    #: This is intended to be the highest-level abstraction that we can muster.
    _chain = []

    #: List of ELF files which are available for mining gadgets
    elfs = []

    #: Stack address where the first byte of the ROP chain lies, if known.
    base = 0

    #: Alignment of the ROP chain; generally the same as the pointer size
    align = 4

    #: Whether or not the ROP chain directly sets the stack pointer to a value
    #: which is not contiguous
    migrated = False

    def __init__(self, elfs, base = None, **kwargs):
        """
        Arguments:
            elfs(list): List of ``pwnlib.elf.ELF`` objects for mining
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
        self.align = max((e.elfclass for e in elfs)) / 8
        self.migrated = False
        self.__load()

    def setRegisters(self, registers):
        """
        Returns an OrderedDict of addresses/values which will set the specified
        register context.

        Arguments:
            registers(dict): Dictionary of ``{register name: value}``

        Returns:
            An OrderedDict of ``{register: sequence of gadgets}``.
        """
        raise NotImplementedError()

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
            return '; '.join(self.gadgets[value]['insns'])
        return ''

    def generatePadding(self, offset, count):
        """
        Generates padding to be inserted into the ROP stack.
        """
        return cyclic.cyclic(offset + count)[-count:]

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

    def build(self, base = None, description = None):
        """
        Construct the ROP chain into a list of elements which can be passed
        to ``pwnlib.util.packing.flat``.

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
            base = self.base

        stack = DescriptiveStack(base)
        chain = copy.deepcopy(self._chain)

        iterable = iter(chain)
        for idx, slot in iterable:

            remaining = len(chain) - idx
            address = base + len(stack) * context.bytes

            if isinstance(slot, (int, long)):
                stack.describe(self.describe(slot))
                stack.append(slot)

            elif isinstance(slot, (str, unicode)):
                stack.describe(self.describe(slot))
                pad = self.generatePadding(len(slot) % context.bytes)
                stack.append(slot)

            elif isinstance(slot, Call):
                stack.describe(self.describe(slot))

                setRegisters = self.setRegisters(slot.registers)

                for register, gadgets in setRegisters:

                    description.setdefault(address, '%s = %s' % (register, self.describe(value)))
                    address += len(gadgets) * context.bytes
                    self.stack.extend(gadgets)

                description.setdefault(address, slot.name)
                stack.append(slot.target)
                address += context.bytes
                newStackElements = slot.stack
                for i, element in enumerate(newStackElements):
                    if not isinstance(element, StackAdjustment):
                        continue
                    if not slot.stack:
                        pass
                    optimize = False
                    if remaining > 1 or isinstance(chain[-1]) and (not isinstance(chain[-1], Call) or not chain[-1].arguments):
                        newStackElements[i] = chain[-1].address
                        next(iterable)

                stack.extend(slot.stack)
            for item in stack:
                if isinstance(object, class_or_type_or_tuple):
                    pass

    def chain(self):
        """Build the ROP chain

        Returns:
            str containing raw ROP bytes
        """
        return packing.flat([ value for addr, value, was_ref in self.build() ], word_size=8 * self.align)

    def dump(self):
        """Dump the ROP chain in an easy-to-read manner"""
        raise NotImplementedError()

    def call(self, resolvable, arguments = (), abi = None):
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

        addr = self.resolve(resolvable)

        if addr:
            self._chain.append(Call(resolvable, addr, arguments, abi))
            return

        syscall_number = getattr(constants, 'SYS_' + resolvable.lower(), None)

        if syscall_number != None:
            log.info('Could not resolve %r. Switching to SROP.' % resolvable)
            self.do_srop(syscall_number, arguments)
            return

        log.error('Could not resolve %r.' % resolvable)

    def do_srop(self, syscall_number, arguments):
        s = None
        with context.local(arch=self.elfs[0].arch):
            s = srop.SigreturnFrame()
            s.pc = self._get_syscall_inst()
            s.syscall = syscall_number
            SYS_sigreturn = constants.SYS_sigreturn
            for register, value in zip(s.arguments, arguments):
                s[register] = value

        # Find a gadget which gives us control of the register we need
        # to set the syscall number
        pop_acc = self.search(regs=[s.syscall_register], order='regs')
        if not pop_acc:
            log.error('No gadget to pop into %s found' % s.syscall_register)

        # Build the stack frame
        self.raw(pop_acc.address)
        self.raw(SYS_sigreturn)
        self.raw(s.pc)
        self.raw(s)

        # Prevent appending to a migrated stack
        if not self.base:
            self.migrated = True

    def _get_syscall_inst(self, **kwargs):
        for instruction in srop.syscall_instructions[context.arch]:
            instruction = getattr(self, instruction, None)
            if instruction is not None:
                return instruction.address
        log.error("Can't find a syscall instruction (%s)" % srop.syscall_instructions[context.arch])

    def raw(self, value):
        """Adds a raw integer or string to the ROP chain.

        If your architecture requires aligned values, then make
        sure that any given string is aligned!

        Arguments:
            data(int/str): The raw value to put onto the rop chain.
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
        leave = self.leave
        if pop_sp and len(pop_sp[1]['regs']) == 1:
            self.raw(pop_sp[0])
            self.raw(next_base)
        elif pop_bp and leave and len(pop_bp[1]['regs']) == 1:
            self.raw(pop_bp[0])
            self.raw(next_base - 4)
            self.raw(leave[0])
        else:
            log.error('Cannot find the gadgets to migrate')
        self.migrated = True

    def __str__(self):
        """Returns: Raw bytes of the ROP chain"""
        return self.chain()

    def __get_cachefile_name(self, elf):
        basename = os.path.basename(elf.file.name)
        sha256 = hashlib.sha256(elf.get_data()).hexdigest()
        cachedir = os.path.join(tempfile.gettempdir(), 'binjitsu-rop-cache')
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
        frame_regs = ['ebp', 'esp'] if self.align == 4 else ['rbp', 'rsp']
        for addr, insns in gadgets.items():
            sp_move = 0
            regs = []
            for insn in insns:
                if pop.match(insn):
                    regs.append(pop.match(insn).group(1))
                    sp_move += self.align
                elif add.match(insn):
                    sp_move += int(add.match(insn).group(1), 16)
                elif ret.match(insn):
                    sp_move += self.align
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
            self.gadgets[addr] = {'insns': insns, 'regs': regs, 'move': sp_move}

            # Don't use 'pop esp' for pivots
            if not set(['rsp', 'esp']) & set(regs):
                self.pivots[sp_move] = addr

        leave = self.search(regs=frame_regs, order='regs')
        if leave and leave.details['regs'] != frame_regs:
            leave = None
        self.leave = leave

    def __repr__(self):
        return 'ROP(%r)' % self.elfs

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
            A tuple of (address, info) in the same format as self.gadgets.items().
        """
        regs = set(regs or [])
        gadget = collections.namedtuple('gadget', ['address', 'details'])

        # Search for an exact match, save the closest match
        # closest = None
        closest_val = (float('inf'), float('inf'), float('inf'))
        for a, i in self.gadgets.items():
            cur_regs = set(i['regs'])
            if regs == cur_regs and move == i['move']:
                return (a, i)

            if not (regs.issubset(cur_regs) and move <= i['move']):
                continue

            if order == 'size':
                cur = (i['move'], len(i['regs']), a)
            else:
                cur = (len(i['regs']), i['move'], a)

            if cur < closest_val:
                closest = gadget(address=a, details=i)
                closest_val = cur

        return closest

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
            count = 4
            if '_' in attr:
                count = int(attr.split('_')[1])
            return self.search(move=count)

        if attr in ('int80', 'syscall', 'sysenter'):
            mapping = {'int80': u'int 0x80',
             u'syscall': u'syscall',
             'sysenter': u'sysenter'}
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
