from pwnlib import log

class MemLeak:
    """MemLeak is a caching and heuristic tool for exploiting memory leaks.

    It will cache leaked memory (which requires either non-randomized static
    data or a continouous session). If required, dynamic or known data can be
    set with the set-functions, but this is usually not required. If a byte
    cannot be recovered, it will try to leak nearby bytes in the hope that the
    byte is recovered as a side-effect.

    """
    def __init__(self, f, search_range = 20, reraise = True):
        self.cache = {}
        self.leak = f
        self.search_range = search_range
        self.reraise = reraise

    def _leak(self, addr):
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

    def raw(self, addr, numb):
        """Leak numb bytes at addr"""
        return [self._leak(addr + i) for i in range(numb)]

    def b(self, addr, ndx = 0):
        """Leak byte at addr"""
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

    def w(self, addr, ndx = 0):
        """Leak word at addr"""
        addr += ndx * 2
        b1 = self.b(addr)
        b2 = self.b(addr + 1)
        if None in [b1, b2]:
            return None
        return b1 + (b2 << 8)

    def d(self, addr, ndx = 0):
        """Leak dword at addr"""
        addr += ndx * 4
        w1 = self.w(addr)
        w2 = self.w(addr + 2)
        if None in [w1, w2]:
            return None
        return w1 + (w2 << 16)

    def q(self, addr, ndx = 0):
        """Leak qword at addr"""
        addr += ndx * 8
        d1 = self.d(addr)
        d2 = self.d(addr + 4)
        if None in [d1, d2]:
            return None
        return d1 + (d2 << 32)

    def s(self, addr):
        """Leak bytes at addr until failure or a nullbyte is found"""
        out = ''
        while True:
            x = self.b(addr)
            if x in [0, None]:
                break
            out += chr(x)
            addr += 1
        return out

    def n(self, addr, numb):
        """Leak numb bytes at addr.

        returns a string with the leaked bytes, will return None if any are missing
        """
        xs = self.raw(addr, numb)
        if None in xs:
            return None
        return ''.join(chr(x) for x in xs)

    def __getitem__(self, addr):
        return self.b(addr)

    def __setitem__(self, addr, val):
        if isinstance(val, (int, long)):
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
                self.cache[addr + n] = ord(c)
        else:
            raise TypeError

    def __delitem__(self, addr):
        del self.cache[addr]

    def setb(self, addr, val, ndx = 0):
        """Set byte at addr to val"""
        addr += ndx
        self[addr] = val & 0xff

    def setw(self, addr, val, ndx = 0):
        """Set word at addr to val"""
        addr += ndx * 2
        self.setb(addr, val)
        self.setb(addr + 1, val >> 8)

    def setd(self, addr, val, ndx = 0):
        """Set dword at addr to val"""
        addr += ndx * 4
        self.setw(addr, val)
        self.setw(addr + 2, val >> 16)

    def setq(self, addr, val, ndx = 0):
        """Set qword at addr to val"""
        addr += ndx * 8
        self.setd(addr, val)
        self.setd(addr + 4, val >> 32)

    def sets(self, addr, val):
        """Set known string at addr, which will be null-terminated"""
        self[addr] = val + '\x00'
