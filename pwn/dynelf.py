import pwn

def gnu_hash(s):
    h = 0
    h = 5381
    for c in s:
        h = h * 33 + ord(c)
    return h & 0xffffffff

class DynELF:
    def __init__(self, path, leak, base = None):
        if isinstance(path, pwn.ELF):
            self.elf = path
        else:
            self.elf = pwn.elf.load(path)
        self.leak = leak
        self.base = base

    def lookup (self, symb, lib = 'libc'):
        if self.elf.elfclass == 'ELF32':
            return self._lookup32(symb, lib)
        if self.elf.elfclass == 'ELF64':
            return self._lookup64(symb, lib)

    def _lookup32 (self, symb, lib):
        pwn.log.bug('Unimplemented')

    def _lookup64 (self, symb, lib):
        base = self.base
        leak = self.leak
        gotoff = self.elf.sections['.got.plt']['addr']
        if base is None:
            pass
            # XXX: Read base address
            # else:
            #     pwn.log.die('Position independent ELF needs a base address')
        else:
            gotplt = base + gotoff

        pwn.log.waitfor('Resolving "%s"' % symb)

        def status(s):
            pwn.log.status('Leaking %s' % s)

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

        status('program headers offset')
        e_phoff = leak.q(libbase + 32)
        e_ph = libbase + e_phoff

        status('.dynamic section offset')
        cur = e_ph
        while True:
            typ = leak.d(cur)
            if typ == 2:
                break
            cur += 7 * 8

        dynoff = leak.q(cur + 16)
        dyn = libbase + dynoff

        status('.gnu.hash, .strtab and .symtab offsets')
        cur = dyn
        gnuhsh = None
        strtab = None
        symtab = None
        while None in [gnuhsh, strtab, symtab]:
            tag = leak.q(cur)
            if   tag == 5:
                strtab = leak.q(cur, 1)
            elif tag == 6:
                symtab = leak.q(cur, 1)
            elif tag == 0x6ffffef5:
                gnuhsh = leak.q(cur, 1)
            cur += 16

        status('.gnu.hash parms')
        nbuckets = leak.d(gnuhsh)
        symndx = leak.d(gnuhsh, 1)
        maskwords = leak.d(gnuhsh, 2)
        shift2 = leak.d(gnuhsh, 3)

        buckets = gnuhsh + 16 + 8 * maskwords
        chains = buckets + 4 * nbuckets

        status('hash chain index')
        hsh = gnu_hash(symb)
        bucket = hsh % nbuckets
        ndx = leak.d(buckets, bucket)
        chain = chains + 4 * (ndx - symndx)
        if ndx == 0:
            pwn.log.failed('Empty chain')
            return None
        status('hash chain')
        i = 0
        while True:
            hsh2 = leak.d(chain)
            if (hsh | 1) == (hsh2 | 1):
                break
            if hsh2 & 1:
                pwn.log.failed('No hash')
                return None
            i += 1
        sym = symtab + 24 * ndx
        status('symbol offset')
        offset = leak.q(sym, 1)
        pwn.log.succeeded()
        return offset + libbase
