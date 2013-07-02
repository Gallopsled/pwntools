import log

class MemLeak:
    def __init__ (self, f, search_range = 20, reraise = True):
        self.cache = {}
        self.leak = f
        self.search_range = search_range
        self.reraise = reraise

    def _leak (self, addr):
        if addr in self.cache:
            return self.cache[addr]
        try:
            x = self.leak(addr)
        except Exception as e:
            if self.reraise:
                raise
            else:
                log.warning('Information leak callback raised an exception: %s' % e.message)
                x = None
        if x is None:
            self.cache[addr] = None
            return None
        bs = list(x)
        for n, b in enumerate(bs):
            self.cache[addr + n] = ord(b)
        return self.cache[addr]

    def b (self, addr, ndx = 0):
        addr += ndx
        x = self._leak(addr)
        if x is not None:
            return x
        # Heuristic: Search around the address hoping to get this byte as a side
        # effect
        for i in range(-self.search_range, 0):
            self._leak(addr + i)
            if addr in self.cache:
                return self.cache[addr]
        for i in range(1, self.search_range + 1):
            self._leak(addr + i)
            if addr in self.cache:
                return self.cache[addr]
        return None

    def w (self, addr, ndx = 0):
        addr += ndx * 2
        b1 = self.b(addr)
        b2 = self.b(addr + 1)
        if None in [b1, b2]:
            return None
        return b1 + (b2 << 8)

    def d (self, addr, ndx = 0):
        addr += ndx * 4
        w1 = self.w(addr)
        w2 = self.w(addr + 2)
        if None in [w1, w2]:
            return None
        return w1 + (w2 << 16)

    def q (self, addr, ndx = 0):
        addr += ndx * 8
        d1 = self.d(addr)
        d2 = self.d(addr + 4)
        if None in [d1, d2]:
            return None
        return d1 + (d2 << 32)

    def s (self, addr):
        out = ''
        while True:
            x = self.b(addr)
            if x in [0, None]:
                break
            out += chr(x)
            addr += 1
        return out

    def n (self, addr, numb):
        xs = self.raw(addr, numb)
        if None in xs:
            return None
        return ''.join(chr(x) for x in xs)

    def __getitem__ (self, addr):
        return self.b(addr)

    def __setitem__ (self, addr, val):
        if isinstance(val, int):
            if val == 0:
                self.cache[addr] = 0
            else:
                n = 0
                while val:
                    self.cache[addr + n] = val & 0xff
                    val >>= 8
                    n += 1
        elif isinstance(val, str):
            for n, c in enumerate(val):
                self.cache[addr + n] = c
        else:
            raise TypeError

    def __delitem__ (self, addr):
        del self.cache[addr]

    def setb (self, addr, val, ndx = 0):
        addr += ndx
        self[addr] = val & 0xff

    def setw (self, addr, val, ndx = 0):
        addr += ndx * 2
        self.setb(addr, val)
        self.setb(addr + 1, val >> 8)

    def setd (self, addr, val, ndx = 0):
        addr += ndx * 4
        self.setw(addr, val)
        self.setw(addr + 2, val >> 16)

    def setq (self, addr, val, ndx = 0):
        addr += ndx * 8
        self.setd(addr, val)
        self.setd(addr + 4, val >> 32)

    def sets (self, addr, val):
        self[addr] = val + '\x00'
