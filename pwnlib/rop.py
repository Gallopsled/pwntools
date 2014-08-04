import hashlib
import os
import ropgadget
import sys
import tempfile

from pwnlib import context, log
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
        """Resolves a symbol to an address

        Args:
            resolvable(str,int): Thing to convert into an address

        Returns:
            int containing address of 'resolvable', or None
        """
        if isinstance(resolvable, str):
            for elf in self.elfs:
                try:    return elf.symbols[resolvable]
                except: pass
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
            try:    return next(name for name,addr in elf.symbols.items() if addr == value)
            except: pass
        if value in self.gadgets:
            return '; '.join(self.gadgets[value]['insns'])
        return ''

    def chain(self, clear=True):
        """Build the ROP chain

        Args:
            clear(bool): Reset the ROP chain after building it (legacy emulation)

        Returns:
            str containging raw ROP bytes
        """
        raw   = ''
        chain = [dict(d) for d in self._chain]

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
        """Add a call to the ROP chain

        Args:
            resolvable(str,int): Value which can be looked up via 'resolve', or is already an integer.
            arguments(list): List of arguments which can be passed to pack().
        """
        addr = self.resolve(resolvable)

        if addr is None:
            raise Exception("Could not resolve %r" % resolvable)

        stackfix_need = (1+len(arguments)) * self.align
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
             'addr':    addr,
             'args':    arguments,
             'retaddr': stackfix_addr,
             'retsize': stackfix_size,
             'pad':     stackfix_size-stackfix_need}

        self._chain.append(d)

    def raw(self, data):
        """Add raw bytes to the ROP chain

        Args:
            data(str): Raw sequence of bytes to add to the ROP chain
        """
        self._chain.append(data)

    def __str__(self):
        """Returns: Raw bytes of the ROP chain"""
        return self.chain(False)

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
                cache = self.__cache_load(elf)
                if cache:
                    gadgets.update(cache)
                    continue

                sys.argv = ['ropgadget', '--binary', elf.path, '--only', 'add|pop|ret', '--nojop', '--nosys']
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

            # Permit duplicates, because blacklisting bytes in the gadget
            # addresses may result in us needing the dupes.
            self.gadgets[addr] = {'insns': insns, 'regs': regs, 'move': sp_move}

            # Don't use 'pop ebp' for pivots
            if 'rbp' not in regs and 'ebp' not in regs:
                self.pivots[sp_move]  = addr

    def __repr__(self):
        return "ROP(%r)" % self.elfs
