import logging
log = logging.getLogger(__name__)

class MemLeak(object):
    """MemLeak is a caching and heuristic tool for exploiting memory leaks.

    It can be used as a decorator, around functions of the form:

      def some_leaker(addr):
          ...
          return data_as_string_or_None

    It will cache leaked memory (which requires either non-randomized static
    data or a continouous session). If required, dynamic or known data can be
    set with the set-functions, but this is usually not required. If a byte
    cannot be recovered, it will try to leak nearby bytes in the hope that the
    byte is recovered as a side-effect.

    Args:
      f (function): The leaker function.
      search_range (int): How many bytes to search backwards in case an address does not work.
      reraise (bool): Whether to reraise call :func:`pwnlib.log.warning` in case the leaker function throws an exception.

    Example:

      .. doctest:: leaker

         >>> binsh = pwnlib.util.misc.read('/bin/sh')
         >>> @pwnlib.memleak.MemLeak
         ... def leaker(addr):
         ...     print "leaking 0x%x" % addr
         ...     return binsh[addr:addr+4]
         >>> leaker.s(0)[:4]
         leaking 0x0
         leaking 0x4
         '\\x7fELF'
         >>> hex(leaker.d(0))
         '0x464c457f'
         >>> hex(leaker.clearb(1))
         '0x45'
         >>> hex(leaker.d(0))
         leaking 0x1
         '0x464c457f'
    """
    def __init__(self, f, search_range = 20, reraise = True):
        self.cache = {}
        self.leak = f
        self.search_range = search_range
        self.reraise = reraise

    def _leak(self, addr):
        """
        """
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
        for n, b in enumerate(x):
            self.cache[addr + n] = ord(b)
        return self.cache[addr]

    def raw(self, addr, numb):
        """Leak `numb` bytes at `addr`"""
        return [self._leak(addr + i) for i in range(numb)]

    def b(self, addr, ndx = 0):
        """b(addr, ndx = 0) -> byte

        Leak byte at ``((uint8_t*) addr)[ndx]``"""
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
        """w(addr, ndx = 0) -> word

        Leak word at ``((uint16_t*) addr)[ndx]``"""
        addr += ndx * 2
        b1 = self.b(addr)
        b2 = self.b(addr + 1)
        if None in [b1, b2]:
            return None
        return b1 + (b2 << 8)

    def d(self, addr, ndx = 0):
        """d(addr, ndx = 0) -> dword

        Leak dword at ``((uint32_t*) addr)[ndx]``"""
        addr += ndx * 4
        w1 = self.w(addr)
        w2 = self.w(addr + 2)
        if None in [w1, w2]:
            return None
        return w1 + (w2 << 16)

    def q(self, addr, ndx = 0):
        """q(addr, ndx = 0) -> qword

        Leak qword at ``((uint64_t*) addr)[ndx]``"""
        addr += ndx * 8
        d1 = self.d(addr)
        d2 = self.d(addr + 4)
        if None in [d1, d2]:
            return None
        return d1 + (d2 << 32)

    def s(self, addr):
        """s(addr) -> str

        Leak bytes at `addr` until failure or a nullbyte is found"""
        out = ''
        while True:
            x = self.b(addr)
            if x in [0, None]:
                break
            out += chr(x)
            addr += 1
        return out

    def n(self, addr, numb):
        """n(addr, ndx = 0) -> str

        Leak `numb` bytes at `addr`.

        Returns:
          A string with the leaked bytes, will return `None` if any are missing
        """
        xs = self.raw(addr, numb)
        if None in xs:
            return None
        return ''.join(chr(x) for x in xs)

    def clearb(self, addr, ndx = 0):
        """clearb(addr, ndx = 0) -> byte

        Clears byte at ``((uint8_t*)addr)[ndx]`` from the cache and
        returns the removed value or `None` if the address was not completely set."""
        addr += ndx
        return self.cache.pop(addr, None)

    def clearw(self, addr, ndx = 0):
        """clearw(addr, ndx = 0) -> word

        Clears word at ``((uint16_t*)addr)[ndx]`` from the cache and
        returns the removed value or `None` if the address was not completely set."""
        addr += ndx * 2
        b1 = self.clearb(addr)
        b2 = self.clearb(addr + 1)
        if None in [b1, b2]:
            return None
        return b1 + (b2 << 8)

    def cleard(self, addr, ndx = 0):
        """cleard(addr, ndx = 0) -> dword

        Clears dword at ``((uint32_t*)addr)[ndx]`` from the cache and
        returns the removed value or `None` if the address was not completely set."""
        addr += ndx * 4
        b1 = self.clearw(addr)
        b2 = self.clearw(addr + 2)
        if None in [b1, b2]:
            return None
        return b1 + (b2 << 16)

    def clearq(self, addr, ndx = 0):
        """clearq(addr, ndx = 0) -> qword

        Clears qword at ``((uint64_t*)addr)[ndx]`` from the cache and
        returns the removed value or `None` if the address was not completely set."""
        addr += ndx * 8
        b1 = self.cleard(addr)
        b2 = self.cleard(addr + 4)
        if None in [b1, b2]:
            return None
        return b1 + (b2 << 32)

    def setb(self, addr, val, ndx = 0):
        """Sets byte at ``((uint8_t*)addr)[ndx]`` to `val` in the cache."""
        addr += ndx
        self.cache[addr] = val & 0xff

    def setw(self, addr, val, ndx = 0):
        """Sets word at ``((uint16_t*)addr)[ndx]`` to `val` in the cache."""
        addr += ndx * 2
        self.setb(addr, val)
        self.setb(addr + 1, val >> 8)

    def setd(self, addr, val, ndx = 0):
        """Sets dword at ``((uint32_t*)addr)[ndx]`` to `val` in the cache."""
        addr += ndx * 4
        self.setw(addr, val)
        self.setw(addr + 2, val >> 16)

    def setq(self, addr, val, ndx = 0):
        """Sets qword at ``((uint64_t*)addr)[ndx]`` to `val` in the cache."""
        addr += ndx * 8
        self.setd(addr, val)
        self.setd(addr + 4, val >> 32)

    def sets(self, addr, val, null_terminate = True):
        """Set known string at `addr`, which will be optionally be null-terminated"""
        for n, c in enumerate(val + ('\x00' if null_terminate else '')):
            self.cache[addr + n] = ord(c)
