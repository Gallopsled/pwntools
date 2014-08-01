import ropgadget
import sys
from pwnlib import context
from pwnlib.elf import ELF
from pwnlib.util.packing import pack, unpack
from pwnlib.util.lists import group
from pwnlib.util.fiddling import enhex

class ROP(object):
    def __init__(self, elfs):
        """
        Args:
            elfs(list): List of pwnlib.elf.ELF objects for mining
        """
        self.elfs  = elfs
        self.clear()
        self.align = context.word_size/8
        self.__load()

    def resolve(self, resolvable):
        """Resolves a symbol to an address"""
        if isinstance(resolvable, str):
            for elf in self.elfs:
                try:    return elf.symbols[resolvable]
                except: pass
        if isinstance(resolvable, int):
            return resolvable
        return None

    def unresolve(self, value):
        """Inverts 'resolve'.  Given an address, it attempts to find a symbol
        for it in the loaded ELF files.  If none is found, it searches all
        known gadgets, and returns the disassembly
        """
        for elf in self.elfs:
            try:    return next(name for name,addr in elf.symbols.items() if addr == value)
            except: pass
        if value in self.gadgets:
            return '; '.join(self.gadgets[value]['insns'])
        return ''

    def chain(self, clear=True):
        """Build the ROP chain"""
        self.cache = {}
        raw   = ''
        chain = list(self._chain)

        if len(chain) == 0:
            return ''

        # If the last call has arguments, there is no need
        # to fix up the stack up for those arguments
        if 0 != len(chain[-1]['args']):
            chain[-1]['retaddr'] = 0xdeadbeef
            chain[-1]['pad']     = 0

        # If the last call does not have any arguments, there is no
        # need to fix up the stack for the second-to-last call.
        # We can put the last call as the 'stackfix' address for
        # the second-to-last call.
        elif  2 <= len(chain) \
        and   0 == len(chain[-1]['args']) \
        and   0 != len(chain[-2]['args']):
            chain[-2]['retaddr'] = chain[-1]['addr']
            chain[-2]['pad']     = 0
            del chain[-1]


        for link in chain:
            if isinstance(link, str):
                raw += link

            # Add the gadget address
            raw += pack(link['addr'])

            # If there are no arguments, there's no need to fix the stack,
            # so continue to the next gadget.
            if len(link['args']) == 0:
                continue

            # Add the return address to fix up the stack
            raw += pack(link['retaddr'])

            # Add the arguments
            for arg in link['args']:
                raw += pack(arg)

            # Add any padding necessary
            raw += link['pad'] * 'X'

        if clear:
            self.clear()

        return raw

    def clear(self):
        """Clear the ROP chain"""
        self._chain = []

    def dump(self):
        """Dump the ROP chain in an easy-to-read manner"""
        result = []
        for chunk in group(self.align, str(self)):
            addr = unpack(chunk)
            line = "%s %#16x %s" % (enhex(chunk), addr, self.unresolve(addr))
            result.append(line)
        return result

    def call(self, resolvable, arguments=()):
        """Add a call to the ROP chain"""
        stackfix_need = len(arguments) * self.align
        stackfix_addr = 0
        stackfix_size = 0

        for size, pivot in sorted(self.pivots.items()):
            if size >= stackfix_need:
                stackfix_addr = pivot
                stackfix_size = size
                break

        if stackfix_addr == 0 and len(arguments) != 0:
            raise Exception("Could not find gadget to clean up stack for call %r %r" % (resolvable,arguments))

        d = {'orig':    resolvable,
             'addr':    self.resolve(resolvable),
             'args':    arguments,
             'retaddr': stackfix_addr,
             'retsize': stackfix_size,
             'pad':     stackfix_size-stackfix_need}

        self._chain.append(d)

    def raw(self, data):
        """Add raw bytes to the ROP chain"""
        self._chain.append(data)

    def __str__(self):
        """Retrieve the raw bytes of the ROP chain"""
        return self.chain(False)

    def __load(self):
        """Load all ROP gadgets for the selected ELF files"""
        #
        # We accept only instructions that look like these.
        #
        # - pop reg
        # - add $sp, value
        # - ret
        #
        # Currently, ROPgadget does not detect multi-byte "C2" ret.
        # https://github.com/JonathanSalwan/ROPgadget/issues/53
        #
        import re

        pop = re.compile(r'^pop (.*)')
        add = re.compile(r'^add .sp, (\S+)$')
        ret = re.compile(r'^ret$')

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
        valid = lambda insn: any(map(lambda pattern: pattern.match(insn), [pop,add,ret]))

        #
        # Currently, ropgadget.args.Args() doesn't take any arguments, and pulls
        # only from sys.argv.  Preserve it through this call.
        #
        argv    = sys.argv
        gadgets = {}
        try:
            for elf in self.elfs:
                sys.argv = ['ropgadget', '--binary', elf.path, '--only', 'add|pop|ret', '--nojop', '--nosys']
                args = ropgadget.args.Args().getArgs()
                core = ropgadget.core.Core(args)
                core.do_binary(elf.path)
                core.do_load(0)

                for gadget in core._Core__gadgets:
                    address = gadget['vaddr'] - elf.load_addr + elf.address
                    insns   = map(str.strip, gadget['gadget'].split(';'))

                    if all(map(valid, insns)):
                        gadgets[address] = insns
        finally:
            sys.argv = argv


        #
        # For each gadget we decided to keep, find out how much it moves the stack,
        # and log which registers it modifies.
        #
        self.gadgets = {}
        self.pivots  = {}

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

            self.gadgets[addr] = {'insns': insns, 'regs': regs, 'move': sp_move}

            # Don't use 'pop ebp' for pivots
            if 'rbp' not in regs and 'ebp' not in regs:
                self.pivots[sp_move]  = addr


