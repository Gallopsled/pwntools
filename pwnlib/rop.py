import hashlib, os, sys, tempfile, re

from . import context, log, elf
from .util import packing, lists

try:
    import ropgadget
    ok = True
except ImportError:
    ok = False

class ROP(object):
    def __init__(self, elfs, base = None):
        """
        Args:
            elfs(list): List of pwnlib.elf.ELF objects for mining
        """
        # Permit singular ROP(elf) vs ROP([elf])
        if isinstance(elfs, elf.ELF):
            elfs = [elfs]
        elif isinstance(elfs, (str, unicode)):
            elfs = [elf.ELF(elfs)]

        self.elfs  = elfs
        self._chain = []
        self.base = base
        self.align = max(e.elfclass for e in elfs)/8
        self.migrated = False
        self.__load()

    def resolve(self, resolvable):
        """Resolves a symbol to an address

        Args:
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

        Args:
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

            output.append([value + '\x00'])
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

                chain.append([addr, [best_pivot], args, best_size/4 - len(args)])

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
                chain[-2][1] = chain[-1][0]
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

    def build(self, base = None):
        """Build the ROP chain into a list (addr, int/string, bool), where the
        last value is True iff the value was an internal reference.

        It is guaranteed that the individual parts are next to each other.

        If there is no base available, then the returned addresses are indexed from 0.

        Args:
          base(int): The base address to build the rop-chain from. Defaults to
                     self.base.
        """

        if base == None:
            base = self.base

        # Use the architecture specific builder to get a [[str/ints/refs]]
        meth = '_build_' + self.elfs[0].get_machine_arch()
        if not hasattr(self, meth):
            log.error("Cannot build rop for architecture %r" % self.get_machine_arch())
        rop = getattr(self, meth)()

        # Stage 1
        #   Generate a dictionary {ref_id: addr}.
        addrs = {}
        if self.base != None:
            addr = self.base
            for i, l in enumerate(rop):
                addrs[i] = addr
                for v in enumerate(l):
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
                        log.bug("ROP: References unknown structure index")
                    else:
                        log.error("ROP: Cannot use structures without a base address")
                else:
                    log.bug("ROP: Unexpected value: %r" % v)

        return out

    def chain(self):
        """Build the ROP chain

        Returns:
            str containging raw ROP bytes
        """

        return packing.flat(
            [value for addr, value, was_ref in self.build()],
            word_size = 8*self.align
        )

    def dump(self):
        """Dump the ROP chain in an easy-to-read manner"""
        result = []

        rop = self.build(self.base or 0)
        addrs = [addr for addr, value, was_ref in rop]
        for addr, value, was_ref in rop:
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
                log.bug("ROP: ROP.build returned an unexpected value %r" % value)

            result.append(line)

        return result

    def call(self, resolvable, arguments=()):
        """Add a call to the ROP chain

        Args:
            resolvable(str,int): Value which can be looked up via 'resolve',
                or is already an integer.
            arguments(list): List of arguments which can be passed to pack().
                Alternately, if a base address is set, arbitrarily nested
                structures of strings or integers can be provided.
        """
        if self.migrated:
            log.error("Cannot append to a migrated chain")

        addr = self.resolve(resolvable)

        if addr is None:
            log.error("Could not resolve %r" % resolvable)

        self._chain.append((addr, arguments))

    def raw(self, value):
        """Adds a raw integer or string to the ROP chain.

        If your architecture requires aligned values, then make
        sure that any given string is aligned!

        Args:
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

        if pop_sp:
            self.raw(pop_sp[0])
            self.raw(next_base)
        elif pop_bp and leave:
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
        md5sum   = hashlib.md5(elf.get_data()).hexdigest()

        filename  = "%s-%s-%#x" % (basename, md5sum, elf.address)

        cachedir  = os.path.join(tempfile.gettempdir(), 'pwntools-rop-cache')

        if not os.path.exists(cachedir):
            os.mkdir(cachedir)

        return os.path.join(cachedir, filename)

    def __cache_load(self, elf):
        filename = self.__get_cachefile_name(elf)

        if os.path.exists(filename):
            log.info("Found gadgets for %r in cache %r" % (elf.file.name,filename))
            return eval(file(filename).read())

    def __cache_save(self, elf, data):
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

        pop   = re.compile(r'^pop (.*)')
        add   = re.compile(r'^add .sp, (\S+)$')
        ret   = re.compile(r'^ret$')
        leave = re.compile(r'^leave$')

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
        valid = lambda insn: any(map(lambda pattern: pattern.match(insn), [pop,add,ret,leave]))

        #
        # Currently, ropgadget.args.Args() doesn't take any arguments, and pulls
        # only from sys.argv.  Preserve it through this call.
        #
        argv    = sys.argv
        gadgets = {}
        try:
            for elf in self.elfs:
                cache = self.__cache_load(elf)
                if cache:
                    gadgets.update(cache)
                    continue

                log.info("Loading gadgets for %r @ %#x" % (elf.path, elf.address))
                sys.argv = ['ropgadget', '--binary', elf.path, '--only', 'add|pop|leave|ret', '--nojop', '--nosys']
                args = ropgadget.args.Args().getArgs()
                core = ropgadget.core.Core(args)
                core.do_binary(elf.path)
                core.do_load(0)

                elf_gadgets = {}
                for gadget in core._Core__gadgets:

                    address = gadget['vaddr'] - elf.load_addr + elf.address
                    insns   = map(str.strip, gadget['gadget'].split(';'))

                    if all(map(valid, insns)):
                        elf_gadgets[address] = insns
                self.__cache_save(elf, elf_gadgets)
                gadgets.update(elf_gadgets)
        finally:
            sys.argv = argv


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
        self.leave = self.search(regs=frame_regs)

    def __repr__(self):
        return "ROP(%r)" % self.elfs

    def search(self, move=0, regs=[]):
        """Search for a gadget which matches the specified criteria.

        Args:
            move(int): Minimum number of bytes by which the stack
                pointer is adjusted.
            regs(list): List of registers which are popped off the stack.
                Order matters, and no other operations are allowed unless
                'move' is expressly set.

        Returns:
            A tuple of (address, info) in the same format as self.gadgets.items().
        """
        if regs and not move:
            move = len(regs)*self.align

        # Search for an exact match, save the closest match
        closest = None
        for a,i in self.gadgets.items():
            # Regs match exactly, move is a minimum
            if not (i['regs'] == regs and move <= i['move']):
                continue

            # Exact match
            if move == i['move']:
                return (a,i)

            # Anything's closer than nothing
            elif not closest:
                closest = (a,i)

            # Closer
            elif i['move'] < closest[1]['move']:
                closest = (a,i)

        return closest

    def __getattr__(self, attr):
        """Helper to make finding ROP gadets easier.
        Also provides a shorthand for .call():
            rop.function(args) ==> rop.call(function, args)

        >>> elf=ELF('/bin/bash')
        >>> rop=ROP([elf])
        >>> rop.rdi     == rop.search(regs=['rdi'])
        True
        >>> rop.r13_r14_r15_rbp == rop.search(regs=['r13','r14','r15','rbp'])
        True
        >>> rop.ret     == rop.search(move=rop.align)
        True
        >>> rop.ret_8   == rop.search(move=8)
        True
        >>> rop.ret     != None
        True
        """
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

        #
        # Check for a '_'-delimited list of registers
        #
        x86_suffixes = ['ax', 'bx', 'cx', 'dx', 'bp', 'sp', 'di', 'si',
                        'r8', 'r9', '10', '11', '12', '13', '14', '15']
        if all(map(lambda x: x[-2:] in x86_suffixes, attr.split('_'))):
            return self.search(regs=attr.split('_'))

        #
        # Otherwise, assume it's a rop.call() shorthand
        #
        def call(*args):
            return self.call(attr,args)
        return call


if not ok:
    def ROP(*args, **kwargs):
        log.error("ROP is not supported without installing libcapstone. See http://www.capstone-engine.org/download.html")
