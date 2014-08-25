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
    @classmethod
    def for_one_lib_only(cls, leak, ptr):
        '''Instantiates and returns a DynELF instance from an arbitrary pointer into a loaded library that can
           resolve symbols in that library only. Can be used for dynamically loaded libraries where the link_map is
           not stable
        '''
        #We need the module base address
        base = cls.find_base(leak, ptr)

        #Now find out elf class
        elfclass = ('ELF32' if leak.b(base + 4) == 1 else 'ELF64')

        return cls(leak, elfclass, libbase = base)

    @classmethod
    def from_lib_ptr(cls, leak, ptr):
        '''Instantiates and returns a DynELF instance from an arbitrary pointer into a loaded library.
        '''
        #We need the module base address
        base = cls.find_base(leak, ptr)

        #Now find out elf class
        elfclass = ('ELF32' if leak.b(base + 4) == 1 else 'ELF64')

        #Now find link_map
        link_map = cls._find_linkmap32(leak, base) if elfclass == 'ELF32' else cls._find_linkmap64(leak, base)

        #And we have everything we need
        return cls(leak, elfclass, link_map = link_map)

    @staticmethod
    def find_base(leak, ptr):
        '''Given a pointer into a library find that librarys base address.'''
        page_mask = ~(4096 - 1)

        #First find base
        while True:
            ptr &= page_mask
            if leak.d(ptr) == 0x464c457f:
                break
            ptr -= 1
        return ptr

    @classmethod
    def _find_dynamic32(cls, leak, base):
        #First find PT_DYNAMIC
        phead = base + leak.d(base + 28)
        while True:
            phtype = leak.d(phead)
            #Check if program header tyep is PT_DYNAMIC
            if phtype == 2:
                break
            #Skip to next
            phead += 32

        #Found dynamic
        dynamic = leak.d(phead + 8)

        #Sometimes this is an offset instead of an address
        if dynamic < base:
            dynamic += base
        return dynamic

    @classmethod
    def _find_linkmap32(cls, leak, base):
        dynamic = cls._find_dynamic32(leak, base)

        #Found dynamic section, now find PLTGOT
        while True:
            dtype = leak.d(dynamic)
            if dtype == 0:
                raise 'Could not find PLTGOT'
            elif dtype == 3:
                break
            #Skip to next
            dynamic += 8

        pltgot = leak.d(dynamic + 4)
        return leak.d(pltgot + 4)

    @classmethod
    def _find_dynamic64(cls, leak, base):
        #First find PT_DYNAMIC
        phead = base + leak.d(base + 32)
        while True:
            phtype = leak.d(phead)
            #Check if program header tyep is PT_DYNAMIC
            if phtype == 2:
                break
            #Skip to next
            phead += 56

        #Now find PLTGOT
        dynamic = leak.q(phead + 16)
        #Sometimes this is an offset instead of an address
        if dynamic < base:
            dynamic += base
        return dynamic


    @classmethod
    def _find_linkmap64(cls, leak, base):
        dynamic = cls._find_dynamic64(leak, base)
        #Found dynamic section, now find PLTGOT
        while True:
            dtype = leak.d(dynamic)
            if dtype == 0:
                raise 'Could not find PLTGOT'
            elif dtype == 3:
                break
            #Skip to next
            dynamic += 16

        pltgot = leak.q(dynamic + 8)
        return leak.q(pltgot + 8)

    @classmethod
    def from_elf(cls, leak, path, base = None):
        '''Get an instance of DynELF initialized from a local ELF file.
           If you have used the constructor previously this method is the one you want.
        '''
        if isinstance(path, elf.ELF):
            elf = path
        else:
            elf = elf.load(path)

        PIE = (elf.elftype == 'DYN')

        #On non position independent executables the base address can be read off the elf.
        if PIE is False and base is None:
            base = filter(lambda x: x['type'] == 'LOAD' and 'E' in x['flg'], elf.segments)[0]['virtaddr']

        #At this point we should have a base address
        if base is None:
            log.die('Position independent ELF needs a base address')

        gotoff = (elf.sections['.got.plt'] if '.got.plt' in elf.sections else elf.sections['.got'])['addr']
        #Sometimes the address is absolute, other times it's an offset relative to the base.
        #Detect which.
        if gotoff > base:
            gotplt = gotoff
        else:
            gotplt = base + gotoff
        
        #Now get address of linkmap
        if elf.elfclass == 'ELF32':
            link_map = leak.d(gotplt, 1)
        else:
            link_map = leak.q(gotplt, 1)

        #We have what we need.
        return cls(leak, elf.elfclass, link_map = link_map)

    def __init__(self, leak, elfclass, link_map = None, libbase = None):
        '''Instantiates a DynELF object. You should not use this directly but rather use one of the
           factory methods: for_one_lib_only(), from_lib_ptr() or from_elf()
        '''
        self.leak = leak
        self.elfclass = elfclass
        self.link_map = link_map
        self.libbase = libbase
        if self.link_map is None and self.libbase is None:
            log.die('Either link_map or libbase needs to be specified')

    def bases(self):
        '''Resolve base addresses of all loaded libraries.

        Return a dictionary mapping library path to its base address.
        '''
        if self.elfclass == 'ELF32':
            return self._bases32()
        if self.elfclass == 'ELF64':
            return self._bases64()

    def lookup (self, symb = None, lib = 'libc'):
        """Find the address of symbol, which is found in lib"""
        log.waitfor('Resolving "%s"' % symb)

        if not self.link_map is None:
            if self.elfclass == 'ELF32':
                return self._lookup32(symb, lib)
            if self.elfclass == 'ELF64':
                return self._lookup64(symb, lib)
        else:
            leak = self.leak
            base = self.libbase
            if self.elfclass == 'ELF32':
                dynamic = DynELF._find_dynamic32(leak, base)
                return self._lookup_in32(symb, base, dynamic)
            else:
                dynamic = DynELF._find_dynamic64(leak, base)
                return self._lookup_in64(symb, base, dynamic)

    def _bases32(self):
        bases = { }
        leak = self.leak

        cur = self.link_map
        while cur:
            addr = leak.d(cur + 4)
            name = leak.s(addr)
            bases[name] = leak.d(cur)
            cur = leak.d(cur + 12)
        return bases

    def _bases64(self):
        bases = { }
        leak = self.leak

        cur = self.link_map
        while cur:
            addr = leak.q(cur + 8)
            name = leak.s(addr)
            bases[name] = leak.q(cur)
            cur = leak.q(cur + 24)
        return bases

    def _lookup32 (self, symb, lib):
        leak = self.leak

        def status(s):
            log.status('Leaking %s' % s)

        status('%s load address' % lib)
        cur = self.link_map
        while True:
            addr = leak.d(cur + 4)
            name = leak.s(addr)
            if lib in name:
                break
            cur = leak.d(cur + 12)
        libbase = leak.d(cur)
        if symb is None:
            return libbase
        dynamic = leak.d(cur, 2)

        return self._lookup_in32(symb, libbase, dynamic)

    def _lookup_in32(self, symb, libbase, dynamic):
        leak = self.leak
        def status(s):
            log.status('Leaking %s' % s)

        status('.gnu.hash/.hash, .strtab and .symtab offsets')
        hshtag = None
        hshtab = None
        strtab = None
        symtab = None
        while None in [hshtab, strtab, symtab]:
            tag = leak.d(dynamic)
            if tag == 4:
                hshtab = leak.d(dynamic, 1)
                hshtag = tag
            elif tag == 5:
                strtab = leak.d(dynamic, 1)
            elif tag == 6:
                symtab = leak.d(dynamic, 1)
            elif tag == 0x6ffffef5:
                hshtab = leak.d(dynamic, 1)
                hshtag = tag
            dynamic += 8

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
                        log.succeeded()
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
                log.failed('Empty chain')
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
                    log.failed('No hash')
                    return None
                i += 1
            status('symbol offset')
            offset = leak.d(sym, 1)
            log.succeeded()
            return offset + libbase

    def _lookup64 (self, symb, lib):
        leak = self.leak

        def status(s):
            log.status('Leaking %s' % s)

        status('%s load address' % lib)
        cur = self.link_map
        while True:
            addr = leak.q(cur + 8)
            name = leak.s(addr)
            if lib in name:
                break
            cur = leak.q(cur + 24)
        libbase = leak.q(cur)
        if symb is None:
            return libbase
        dynamic = leak.q(cur, 2)

        return self._lookup_in64(symb, libbase, dynamic)

    def _lookup_in64(self, symb, libbase, dynamic):
        leak = self.leak
        def status(s):
            log.status('Leaking %s' % s)

        status('.gnu.hash/.hash, .strtab and .symtab offsets')
        hshtag = None
        hshtab = None
        strtab = None
        symtab = None
        while None in [hshtab, strtab, symtab]:
            tag = leak.q(dynamic)
            if   tag == 4:
                hshtab = leak.q(dynamic, 1)
                hshtag = tag
            elif tag == 5:
                strtab = leak.q(dynamic, 1)
            elif tag == 6:
                symtab = leak.q(dynamic, 1)
            elif tag == 0x6ffffef5:
                hshtab = leak.q(dynamic, 1)
                hshtag = tag
            dynamic += 16

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
                        log.succeeded()
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
                log.failed('Empty chain')
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
                    log.failed('No hash')
                    return None
                i += 1
            status('symbol offset')
            offset = leak.q(sym, 1)
            log.succeeded()
            return offset + libbase
