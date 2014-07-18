from . import elf, log, memleak

def sysv_hash(symbol):
    """sysv_hash(str) -> int

    Fallback hash function used in ELF files if .gnuhash is not present
    """
    h = 0
    g = 0
    for c in symbol:
        h = (h << 4) + ord(c)
        g = h & 0xf0000000
        h ^= (g >> 24)
        h &= ~g
    return h & 0xffffffff

def gnu_hash(s):
    """gnu_hash(str) -> int

    Hash function used in the .gnuhash section of ELF files
    """
    h = 5381
    for c in s:
        h = h * 33 + ord(c)
    return h & 0xffffffff

class DynELF:
    """DynELF is a tool for finding symbol addresses by leaking data from the .dynsym section.

    Args:
        path (filename/ELF object): the ELF file
        leak (MemLeak object): a memory leak for the ELF file
        base (int): base address for the binary
    """
    def __init__(self, path, leak, base = None):
        if isinstance(path, elf.ELF):
            self.elf = path
        else:
            self.elf = elf.load(path)
        if isinstance(leak, memleak.MemLeak):
            self.leak = leak
        else:
            log.error('Leak must be a MemLeak object')

        self.PIE = (self.elf.elftype == 'DYN')
        self.base = base
        if self.PIE is False and self.base is None:
            self.base = filter(lambda x: x['type'] == 'LOAD' and 'E' in x['flg'], self.elf.segments)[0]['virtaddr']
        if self.base is None:
            log.error('Position independent ELF needs a base address')

    def bases(self):
        """Resolve base addresses of all loaded libraries.

        Return a dictionary mapping library path to its base address.
        """
        if self.elf.elfclass == 'ELF32':
            return self._bases32()
        if self.elf.elfclass == 'ELF64':
            return self._bases64()

    def lookup (self, symb = None, lib = 'libc'):
        """Find the address of symbol, which is found in lib"""
        if self.elf.elfclass == 'ELF32':
            return self._lookup32(symb, lib)
        if self.elf.elfclass == 'ELF64':
            return self._lookup64(symb, lib)

    def _gotoff(self):
        sections = self.elf.sections
        return (sections['.got.plt'] if '.got.plt' in sections else sections['.got'])['addr']

    def _bases32(self):
        bases = { }
        base = self.base
        leak = self.leak
        gotoff = self._gotoff()
        if base is None:
            pass
            # XXX: Read base address
            # else:
            #     log.error('Position independent ELF needs a base address')
        else:
            if gotoff > base:
                gotplt = gotoff
            else:
                gotplt = base + gotoff

        link_map = leak.d(gotplt, 1)

        cur = link_map
        while cur:
            addr = leak.d(cur + 4)
            name = leak.s(addr)
            bases[name] = leak.d(cur)
            cur = leak.d(cur + 12)
        return bases

    def _bases64(self):
        bases = { }
        base = self.base
        leak = self.leak
        gotoff = self._gotoff()
        if base is None:
            pass
            # XXX: Read base address
            # else:
            #     log.error('Position independent ELF needs a base address')
        else:
            if gotoff > base:
                gotplt = gotoff
            else:
                gotplt = base + gotoff

        link_map = leak.q(gotplt, 1)

        cur = link_map
        while cur:
            addr = leak.q(cur + 8)
            name = leak.s(addr)
            bases[name] = leak.q(cur)
            cur = leak.q(cur + 24)
        return bases

    def _lookup32 (self, symb, lib):
        base = self.base
        leak = self.leak
        gotoff = self._gotoff()
        if base is None:
            pass
            # XXX: Read base address
            # else:
            #     log.error('Position independent ELF needs a base address')
        else:
            if gotoff > base:
                gotplt = gotoff
            else:
                gotplt = base + gotoff

        log.waitfor('Resolving "%s"' % symb)

        def status(s):
            log.status('Leaking %s' % s)

        status('link_map')
        link_map = leak.d(gotplt, 1)

        status('%s load address' % lib)
        cur = link_map
        while True:
            addr = leak.d(cur + 4)
            name = leak.s(addr)
            if lib in name:
                break
            cur = leak.d(cur + 12)
        libbase = leak.d(cur)
        if symb is None:
            return libbase
        dyn = leak.d(cur, 2)

        status('.gnu.hash, .strtab and .symtab offsets')
        cur = dyn
        hshtag = None
        hshtab = None
        strtab = None
        symtab = None
        while None in [hshtab, strtab, symtab]:
            tag = leak.d(dyn)
            if tag == 4:
                hshtab = leak.d(dyn, 1)
                hshtag = tag
            elif tag == 5:
                strtab = leak.d(dyn, 1)
            elif tag == 6:
                symtab = leak.d(dyn, 1)
            elif tag == 0x6ffffef5:
                hshtab = leak.d(dyn, 1)
                hshtag = tag
            dyn += 8

        # with glibc the pointers are relocated whereas with f.x. uclibc they
        # are not
        if libbase > strtab:
            strtab += libbase
            symtab += libbase
            hshtab += libbase

        if hshtag == 4:
            status('.hash parms')
            nbuckets = leak.d(hshtab)
            bucketaddr = hshtab + 8
            chain = hshtab + 8 + nbuckets * 4

            status('hashmap')
            h = sysv_hash(symb) % nbuckets
            idx = leak.d(bucketaddr, h)
            while idx:
                sym = symtab + (idx * 16)
                symtype = leak.b(sym + 12) & 0xf
                if symtype == 2:
                    #Function type symbol
                    name = leak.s(strtab + leak.d(sym))
                    if name == symb:
                        #Bingo
                        log.done_success()
                        return libbase + leak.d(sym, 1)
                idx = leak.d(chain, idx)
        else:
            status('.gnu.hash parms')
            nbuckets = leak.d(hshtab)
            symndx = leak.d(hshtab, 1)
            maskwords = leak.d(hshtab, 2)

            buckets = hshtab + 16 + 4 * maskwords
            chains = buckets + 4 * nbuckets

            status('hash chain index')
            hsh = gnu_hash(symb)
            bucket = hsh % nbuckets
            ndx = leak.d(buckets, bucket)
            chain = chains + 4 * (ndx - symndx)
            if ndx == 0:
                log.done_failure('Empty chain')
                return None
            status('hash chain')
            i = 0
            hsh &= ~1
            while True:
                hsh2 = leak.d(chain + (i * 4))
                if hsh == (hsh2 & ~1):
                    #Hash matches, but this may be a collision
                    #Check symbol name too.
                    sym = symtab + 16 * (ndx + i)
                    name = leak.s(strtab + leak.d(sym))
                    if name == symb:
                        break
                if hsh2 & 1:
                    log.done_failure('No hash')
                    return None
                i += 1
            status('symbol offset')
            offset = leak.d(sym, 1)
            log.done_success()
            return offset + libbase

    def _lookup64 (self, symb, lib):
        base = self.base
        leak = self.leak
        gotoff = self._gotoff()
        if base is None:
            pass
            # XXX: Read base address
            # else:
            #     log.error('Position independent ELF needs a base address')
        else:
            if gotoff > base:
                gotplt = gotoff
            else:
                gotplt = base + gotoff

        log.waitfor('Resolving "%s"' % symb)

        def status(s):
            log.status('Leaking %s' % s)

        status('link_map')
        link_map = leak.q(gotplt, 1)

        status('%s load address' % lib)
        cur = link_map
        while True:
            addr = leak.q(cur + 8)
            name = leak.s(addr)
            if lib in name:
                break
            cur = leak.q(cur + 24)
        libbase = leak.q(cur)
        if symb is None:
            return libbase
        dyn = leak.q(cur, 2)

        status('.gnu.hash/.hash, .strtab and .symtab offsets')
        cur = dyn
        hshtag = None
        hshtab = None
        strtab = None
        symtab = None
        while None in [hshtab, strtab, symtab]:
            tag = leak.q(cur)
            if   tag == 4:
                hshtab = leak.q(cur, 1)
                hshtag = tag
            elif tag == 5:
                strtab = leak.q(cur, 1)
            elif tag == 6:
                symtab = leak.q(cur, 1)
            elif tag == 0x6ffffef5:
                hshtab = leak.q(cur, 1)
                hshtag = tag
            cur += 16

        # with glibc the pointers are relocated whereas with f.x. uclibc they
        # are not
        if libbase > strtab:
            strtab += libbase
            symtab += libbase
            hshtab += libbase

        if hshtag == 4:
            status('.hash parms')
            nbuckets = leak.d(hshtab)
            bucketaddr = hshtab + 8
            chain = hshtab + 8 + nbuckets * 4

            status('hashmap')
            h = sysv_hash(symb) % nbuckets
            idx = leak.d(bucketaddr, h)
            while idx:
                sym = symtab + (idx * 24)
                symtype = leak.b(sym + 4) & 0xf
                if symtype == 2:
                    #Function type symbol
                    name = leak.s(strtab + leak.d(sym))
                    if name == symb:
                        #Bingo
                        log.done_success()
                        return libbase + leak.q(sym, 1)
                idx = leak.d(chain, idx)
        else:
            status('.gnu.hash parms')
            nbuckets = leak.d(hshtab)
            symndx = leak.d(hshtab, 1)
            maskwords = leak.d(hshtab, 2)

            buckets = hshtab + 16 + 8 * maskwords
            chains = buckets + 4 * nbuckets

            status('hash chain index')
            hsh = gnu_hash(symb)
            bucket = hsh % nbuckets
            ndx = leak.d(buckets, bucket)
            chain = chains + 4 * (ndx - symndx)
            if ndx == 0:
                log.done_failure('Empty chain')
                return None
            status('hash chain')
            i = 0
            hsh &= ~1
            while True:
                hsh2 = leak.d(chain + (i * 4))
                if hsh == (hsh2 & ~1):
                    #Hash matches, but this may be a collision
                    #Check symbol name too.
                    sym = symtab + 24 * (ndx + i)
                    name = leak.s(strtab + leak.d(sym))
                    if name == symb:
                        break
                if hsh2 & 1:
                    log.done_failure('No hash')
                    return None
                i += 1
            status('symbol offset')
            offset = leak.q(sym, 1)
            log.done_success()
            return offset + libbase
