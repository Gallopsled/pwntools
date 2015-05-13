"""Return Oriented Programming
"""
import hashlib
import os
import re
import sys
import tempfile
import collections

from .elf import ELF
from .log import getLogger
from .util import packing

from srop import SigreturnFrame, get_registers
from .context import context
from util.packing import *
import constants

log = getLogger(__name__)

class ROP(object):
    """Class which simplifies the generation of ROP-chains.

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
       # '\\xfc\\x82\\x04\\x08\\xef\\xbe\\xad\\xde\\x00\\x00\\x00\\x00\\xa8\\x96\\x04\\x08'

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
    def __init__(self, elfs, base = None, **kwargs):
        """
        Arguments:
            elfs(list): List of pwnlib.elf.ELF objects for mining
        """

        import ropgadget

        # Permit singular ROP(elf) vs ROP([elf])
        if isinstance(elfs, ELF):
            elfs = [elfs]
        elif isinstance(elfs, (str, unicode)):
            elfs = [ELF(elfs)]

        self.elfs  = elfs
        self._chain = []
        self.base = base
        self.align = max(e.elfclass for e in elfs)/8
        self.migrated = False
        self.__load()

        # Used by dump() so that it knows where the SROP chain
        # begins. Indicates an index into the result returned
        # by self.build.
        self.srop_start_index = -1

        # Cached address of a syscall instruction
        self._syscall_instruction = None

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
        if isinstance(resolvable, (int,long)):
            return resolvable
        return None

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

    def _output_struct(self, value, output):
        next_index = len(output)

        if isinstance(value, (int, long)):
            return value
        elif isinstance(value, (unicode, str)):
            if isinstance(value, unicode):
                value = value.encode('utf8')

            while True:
                value += '\x00'
                if len(value) % self.align == 0:
                    break

            output.append([value])
            return (next_index,)
        elif isinstance(value, (tuple, list)):
            l = []
            output.append(l)
            for v in value:
                l.append(self._output_struct(v, output))
            return (next_index,)
        else:
            log.error("ROP: Cannot flatten value %r" % value)

    def _build_x86(self):
        # Stage 1:
        #   Convert every call in self._chain from a (addr, args) tuple
        #   into a (addr, pivot, args, pad) tuple.
        #
        # Stage 2:
        #   Micro-optimizations for the last call in the chain.
        #
        # Stage 3:
        #   Convert into a [[str/ints/refs]], where
        #   refs are references to one of the first lists and will be turned
        #   into pointers outside this function. Refs are represented as
        #   length-1 tuples.

        if not self._chain:
            return []

        # Stage 1
        chain = []
        for addr, args in self._chain:
            if not args:
                chain.append([addr, [], [], 0])
            else:
                need = (1+len(args)) * self.align
                best_pivot = None
                best_size  = None

                for size, pivot in sorted(self.pivots.items()):
                    if size >= need:
                        best_pivot = pivot
                        best_size  = size
                        break

                if best_pivot == None:
                    log.error("Could not find gadget to clean up stack for call %r %r" % (addr, args))

                chain.append([addr, [best_pivot], args, best_size/4 - len(args) - 1])

        # Stage 2
        # If the last call has arguments, there is no need
        # to fix up the stack up for those arguments
        if chain[-1][2]:
            chain[-1][1] = [0xdeadbeef]
            chain[-1][3] = 0

        # If the last call does not have any arguments, there is no
        # need to fix up the stack for the second-to-last call.
        # We can put the last call as the pivot address for
        # the second-to-last call.
        if len(chain) > 1 and not chain[-1][2] and chain[-2][2]:
            # This optimization does not work if a raw string is on the stack
            if not isinstance(chain[-1][0], (str, unicode)):
                chain[-2][1] = [chain[-1][0]]
                chain[-2][3] = 0
                chain.pop()

        # Stage 3
        outrop = []
        output = [outrop]

        for addr, pivot, args, pad in chain:
            outrop.append(addr)
            outrop.extend(pivot)
            for arg in args:
                outrop.append(self._output_struct(arg, output))
            for _ in range(pad):
                outrop.append('$$$$')

        return output

    _build_i386 = _build_x86

    def build(self, base = None):
        """Build the ROP chain into a list (addr, int/string, bool), where the
        last value is True iff the value was an internal reference.

        It is guaranteed that the individual parts are next to each other.

        If there is no base available, then the returned addresses are indexed from 0.

        Arguments:
          base(int): The base address to build the rop-chain from. Defaults to
                     self.base.
        """

        if base == None:
            base = self.base

        # Use the architecture specific builder to get a [[str/ints/refs]]
        meth = '_build_' + self.elfs[0].get_machine_arch()
        if not hasattr(self, meth):
            log.error("Cannot build rop for architecture %r" % self.elfs[0].get_machine_arch())
        rop = getattr(self, meth)()

        # Stage 1
        #   Generate a dictionary {ref_id: addr}.
        addrs = {}
        if base != None:
            addr = base
            for i, l in enumerate(rop):
                addrs[i] = addr
                for v in l:
                    if isinstance(v, (int, long, tuple)):
                        addr += self.align
                    else:
                        addr += len(v)

        # Stage 2:
        #   Convert into [(addr, int/string, bool)]
        addr = base or 0
        out = []
        for l in rop:
            for v in l:
                if isinstance(v, (int, long)):
                    out.append((addr, v, False))
                    addr += self.align
                elif isinstance(v, str):
                    out.append((addr, v, False))
                    addr += len(v)
                elif isinstance(v, tuple):
                    if v[0] in addrs:
                        out.append((addr, addrs[v[0]], True))
                        addr += self.align
                    elif base != None:
                        log.error("ROP: References unknown structure index")
                    else:
                        log.error("ROP: Cannot use structures without a base address")
                else:
                    log.error("ROP: Unexpected value: %r" % v)

        return out


    def chain(self):
        """Build the ROP chain

        Returns:
            str containing raw ROP bytes
        """

        return packing.flat(
            [value for addr, value, was_ref in self.build()],
            word_size = 8*self.align
        )

    def dump(self):
        """Dump the ROP chain in an easy-to-read manner"""
        result = []

        def _get_next_sropreg():
            registers = get_registers()
            for eachreg in registers:
                yield eachreg

        nextreg = _get_next_sropreg()
        rop = self.build(self.base or 0)
        addrs = [addr for addr, value, was_ref in rop]
        for pos, content in enumerate(rop):
            addr, value, was_ref = content
            if self.srop_start_index != -1 and pos >= self.srop_start_index:
                assert isinstance(value, (int, long)) == True
                line = "0x%04x: %#16x%s" % (
                        addr,
                        value,
                        (' (%s)' % next(nextreg))
                        )

            else:
                if isinstance(value, str):
                    line   = "0x%04x: %16r" % (addr, value.rstrip('\x00'))
                elif isinstance(value, (int, long)):
                    if was_ref:
                        line = "0x%04x: %#16x (%+d)" % (
                            addr,
                            value,
                            value - addr
                        )
                    else:
                        ref = self.unresolve(value)
                        line = "0x%04x: %#16x%s" % (
                            addr,
                            value,
                            (' (%s)' % ref) if ref else ''
                        )
                else:
                    log.error("ROP: ROP.build returned an unexpected value %r" % value)

            result.append(line)

        return '\n'.join(result)

    def _get_syscall_inst(self, **kwargs):
        instructions = None
        with context.local(**kwargs):
            arch_syscall_mapping = {"i386" : ["int80", "sysenter"],
                                    "amd64": ["syscall"]}
            instructions = arch_syscall_mapping[context.arch]

        if self._syscall_instruction:
            return self._syscall_instruction

        for each_instruction in instructions:
            try:
                self._syscall_instruction = self.__getattr__(each_instruction).address
                return self._syscall_instruction
            except AttributeError, e:
                log.info("Unable to find '%s' instruction" % each_instruction)
        log.error("Unable to find any syscall instructions")

    def call(self, resolvable, arguments=()):
        """Add a call to the ROP chain

        Arguments:
            resolvable(str,int): Value which can be looked up via 'resolve',
                or is already an integer.
            arguments(list): List of arguments which can be passed to pack().
                Alternately, if a base address is set, arbitrarily nested
                structures of strings or integers can be provided.
        """
        if self.migrated:
            log.error("Cannot append to a migrated chain")

        addr = self.resolve(resolvable)

        if addr:
            self._chain.append((addr, arguments))
            return

        syscall_name = "SYS_" + resolvable.lower()
        syscall_number = getattr(constants, syscall_name, None)

        if syscall_number == None:
            log.error("Could not resolve %r." % resolvable)

        log.info("Could not resolve %r. Switching to SROP." % resolvable)
        self.do_srop(syscall_number, arguments)


    def do_srop(self, syscall_number, arguments, **kwargs):
        sigreturn_number, register = None, None
        with context.local(**kwargs):
            sigreturn_syscalls = {"i386": (0x77, "eax"), "amd64": (0xf, "rax")}
            sigreturn_number, register = sigreturn_syscalls[context.arch]

        try:
            pop_acc = self.search(regs=[register], order='regs').address
        except TypeError, e:
            log.error("No gadget to pop into %s found" % register)

        SYSCALL_INST = self._get_syscall_inst()

        # First, we need to pop the system call number of "sigreturn" into
        # eax.
        self.raw(pop_acc)
        self.raw(sigreturn_number)

        # Second, we call the syscall instruction to execute the "sigreturn"
        # system call
        self.raw(SYSCALL_INST)

        # Third, we need to construct an SROP frame that calls the required
        # system call
        frame, sp_pos = self.get_sigreturnframe(syscall_number, arguments)
        frame = unpack_many(frame)
        self.srop_start_index = len(self.build())
        for each in frame:
            self.raw(each)

        # If the base is specified, we can continue setting up our chain
        # even after the SROP call
        if self.base:
            # Find where in self._chain we have the stack pointer
            sp_index = len(self._chain) - len(frame) + sp_pos

            # Find the new sp value that we need to store in the stack
            # pointer
            size = None
            with context.local(**kwargs):
                sizes = {"i386": 4, "amd64": 8}
                size  = sizes[context.arch]
            new_spval = self.base + (self.srop_start_index*size) + len(frame)*size

            # Replace the sp value with the right address
            self._chain[sp_index] = (new_spval, ())


    def get_sigreturnframe(self, syscall_number, arguments, **kwargs):
        argregisters_amd64 = ["rax", "rip", "rdi", "rsi", "rdx", "r10", "r8", "r9"]
        argregisters_i386  = ["eax", "eip", "ebx", "ecx", "edx", "esi", "edi", "ebp"]

        with context.local(**kwargs):
            reg_arch_mapping = {"i386": argregisters_i386, "amd64": argregisters_amd64}
            registers = reg_arch_mapping[context.arch]

            SYSCALL_INST = self._get_syscall_inst()

            s = SigreturnFrame()
            s.set_regvalue(registers[0], syscall_number)
            s.set_regvalue(registers[1], SYSCALL_INST)

            for register, value in zip(registers[2:], arguments):
                s.set_regvalue(register, value)

            # Returns the frame and the position of the stack pointer on the SROP
            # frame
            return s.get_frame(), s.get_spindex()

    def raw(self, value):
        """Adds a raw integer or string to the ROP chain.

        If your architecture requires aligned values, then make
        sure that any given string is aligned!

        Arguments:
            data(int/str): The raw value to put onto the rop chain.
        """

        if self.migrated:
            log.error("Cannot append to a migrated chain")

        self._chain.append((value, ()))

    def migrate(self, next_base):
        """Explicitly set $sp, by using a ``leave; ret`` gadget"""

        if isinstance(next_base, ROP):
            next_base = self.base

        pop_sp = self.rsp or self.esp
        pop_bp = self.rbp or self.ebp
        leave  = self.leave

        if pop_sp and len(pop_sp[1]['regs']) == 1:
            self.raw(pop_sp[0])
            self.raw(next_base)
        elif pop_bp and leave and len(pop_bp[1]['regs']) == 1:
            self.raw(pop_bp[0])
            self.raw(next_base-4)
            self.raw(leave[0])
        else:
            log.error("Cannot find the gadgets to migrate")

        self.migrated = True

    def __str__(self):
        """Returns: Raw bytes of the ROP chain"""
        return self.chain()

    def __get_cachefile_name(self, elf):
        basename = os.path.basename(elf.file.name)
        sha256   = hashlib.sha256(elf.get_data()).hexdigest()
        cachedir  = os.path.join(tempfile.gettempdir(), 'binjitsu-rop-cache')

        if not os.path.exists(cachedir):
            os.mkdir(cachedir)

        return os.path.join(cachedir, sha256)

    def __cache_load(self, elf):
        filename = self.__get_cachefile_name(elf)

        if not os.path.exists(filename):
            return None

        log.info_once("Loaded cached gadgets for %r" % elf.file.name)
        gadgets = eval(file(filename).read())

        # Gadgets are saved with their 'original' load addresses.
        gadgets = {k-elf.load_addr+elf.address:v for k,v in gadgets.items()}

        return gadgets

    def __cache_save(self, elf, data):
        # Gadgets need to be saved with their 'original' load addresses.
        data = {k+elf.load_addr-elf.address:v for k,v in data.items()}

        file(self.__get_cachefile_name(elf),'w+').write(repr(data))

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
        argv    = sys.argv
        stdout  = sys.stdout
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

            log.info_once("Loading gadgets for %r" % elf.path)

            try:
                sys.stdout = Wrapper(sys.stdout)

                import ropgadget
                sys.argv = ['ropgadget', '--binary', elf.path, '--only', 'sysenter|syscall|int|add|pop|leave|ret', '--nojop']
                args = ropgadget.args.Args().getArgs()
                core = ropgadget.core.Core(args)
                core.do_binary(elf.path)
                core.do_load(0)
            finally:
                sys.argv   = argv
                sys.stdout = stdout

            elf_gadgets = {}
            for gadget in core._Core__gadgets:

                address = gadget['vaddr'] - elf.load_addr + elf.address
                insns   = [g.strip() for g in gadget['gadget'].split(';')]

                if all(map(valid, insns)):
                    elf_gadgets[address] = insns
            self.__cache_save(elf, elf_gadgets)
            gadgets.update(elf_gadgets)

        #
        # For each gadget we decided to keep, find out how much it moves the stack,
        # and log which registers it modifies.
        #
        self.gadgets = {}
        self.pivots  = {}

        frame_regs = ['ebp','esp'] if self.align == 4 else ['rbp','rsp']

        for addr,insns in gadgets.items():
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
                    regs    += frame_regs

            # Permit duplicates, because blacklisting bytes in the gadget
            # addresses may result in us needing the dupes.
            self.gadgets[addr] = {'insns': insns, 'regs': regs, 'move': sp_move}

            # Don't use 'pop esp' for pivots
            if not set(['rsp','esp']) & set(regs):
                self.pivots[sp_move]  = addr

        #
        # HACK: Set up a special '.leave' helper.  This is so that
        #       I don't have to rewrite __getattr__ to support this.
        #
        leave = self.search(regs = frame_regs, order = 'regs')
        if leave and leave.details['regs'] != frame_regs:
            leave = None
        self.leave = leave

    def __repr__(self):
        return "ROP(%r)" % self.elfs

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
        closest = None
        closest_val = (float('inf'), float('inf'), float('inf'))
        for a,i in self.gadgets.items():
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

        elif attr in ["int80", "syscall", "sysenter"]:
            mapping = {"int80": u"int 0x80", u"syscall": u"syscall",
                       "sysenter": u"sysenter"}
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
            return self.search(regs = attr.split('_'), order = 'regs')

        #
        # Otherwise, assume it's a rop.call() shorthand
        #
        def call(*args):
            return self.call(attr,args)
        return call
