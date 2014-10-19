import logging
from .util.packing import unpack
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
        self.leak = f
        self.search_range = search_range
        self.reraise = reraise

        # Map of address: byte for all bytes received
        self.cache = {}

    def _leak(self, addr, n):
        addresses = [addr+i for i in xrange(n)]
        for address in addresses:
            # Cache hit
            if address in self.cache:
                continue

            # Cache miss, get the data from the leaker
            data = None
            try:
                data = self.leak(addr)
            except Exception as e:
                if self.reraise:
                    raise

            # We could not leak this particular byte, search backwardd
            # to see if another request will satisfy it
            if not data:
                for i in range(1, self.search_range):
                    data = self._leak(address-i, i)
                    if data:
                        break

            # Could not receive any data, even overlapped with previous
            # requests.
            if not data:
                return None

            # Fill cache for as many bytes as we received
            for i,byte in enumerate(data):
                self.cache[address+i] = byte

        # Ensure everything is in the cache
        if not all(a in cache for a in addresses):
            return None

        # Cache is filled, satisfy the request
        return ''.join(self.cache[addr+i] for i in xrange(n))

    def raw(self, addr, numb):
        """raw(addr, numb) -> list

        Leak `numb` bytes at `addr`"""
        return map(self._leak, range(addr, addr+i))

    def b(self, addr, ndx = 0):
        """b(addr, ndx = 0) -> int

        Leak byte at ``((uint8_t*) addr)[ndx]``"""
        addr += ndx
        data = self._leak(addr, 1)
        return None if not data else unpack('all', data)

    def w(self, addr, ndx = 0):
        """w(addr, ndx = 0) -> int

        Leak word at ``((uint16_t*) addr)[ndx]``"""
        addr += ndx * 2
        data = self._leak(addr, 2)
        return None if not data else unpack('all', data)

    def d(self, addr, ndx = 0):
        """d(addr, ndx = 0) -> int

        Leak dword at ``((uint32_t*) addr)[ndx]``"""
        addr += ndx * 4
        data = self._leak(addr, 4)
        return None if not data else unpack('all', data)

    def q(self, addr, ndx = 0):
        """q(addr, ndx = 0) -> int

        Leak qword at ``((uint64_t*) addr)[ndx]``"""
        addr += ndx * 8
        data = self._leak(addr, 8)
        return None if not data else unpack('all', data)

    def s(self, addr):
        """s(addr) -> str

        Leak bytes at `addr` until failure or a nullbyte is found"""

        # This relies on the behavior of _leak to fill the cache
        orig = addr
        while self.b(addr):
            addr += 1
        return self._leak(orig, addr-orig)

    def n(self, addr, numb):
        """n(addr, ndx = 0) -> str

        Leak `numb` bytes at `addr`.

        Returns:
          A string with the leaked bytes, will return `None` if any are missing
        """
        return self._leak(addr, numb) or None

    def clearb(self, addr, ndx = 0):
        """clearb(addr, ndx = 0) -> byte

        Clears byte at ``((uint8_t*)addr)[ndx]`` from the cache and
        returns the removed value or `None` if the address was not completely set."""
        size  = 1
        addr += ndx * size
        data  = self.cache.pop(addr, None)
        return None if data is None else unpack('all', ''.join(data))

    def clearw(self, addr, ndx = 0):
        """clearw(addr, ndx = 0) -> word

        Clears word at ``((uint16_t*)addr)[ndx]`` from the cache and
        returns the removed value or `None` if the address was not completely set."""
        size   = 2
        addr  += ndx * size
        data   = map(self.clearb, range(addr, addr+size))
        return None if None in data else unpack(''.join(data), word_size='all')

    def cleard(self, addr, ndx = 0):
        """cleard(addr, ndx = 0) -> dword

        Clears dword at ``((uint32_t*)addr)[ndx]`` from the cache and
        returns the removed value or `None` if the address was not completely set."""
        size   = 4
        addr  += ndx * size
        data   = map(self.clearb, range(addr, addr+size))
        return None if None in data else unpack(''.join(data), word_size='all')

    def clearq(self, addr, ndx = 0):
        """clearq(addr, ndx = 0) -> qword

        Clears qword at ``((uint64_t*)addr)[ndx]`` from the cache and
        returns the removed value or `None` if the address was not completely set.

        >>> c = MemLeak(lambda addr: '')
        >>> c.cache = {x:'x' for x in range(0x100, 0x108)}
        >>> c.clearq(0x100)
        >>> c.cache == {}
        True

        """
        size   = 8
        addr  += ndx * size
        data   = map(self.clearb, range(addr, addr+size))
        return None if None in data else unpack(''.join(data), word_size='all')

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
