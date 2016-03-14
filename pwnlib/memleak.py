from .log import getLogger
from .util.packing import pack
from .util.packing import unpack

log = getLogger(__name__)

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

    Arguments:
        f (function): The leaker function.
        search_range (int): How many bytes to search backwards in case an address does not work.
        reraise (bool): Whether to reraise call :func:`pwnlib.log.warning` in case the leaker function throws an exception.

    Example:

        .. doctest:: leaker

            >>> import pwnlib
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
            >>> @pwnlib.memleak.MemLeak
            ... def leaker(addr):
            ...     if addr & 0xff == 0:
            ...         print "leaker failed 0x%x" % addr
            ...         return
            ...     print "leaking 0x%x" % addr
            ...     return binsh[addr:addr+4]
            >>> leaker.d(0)
            leaker failed 0x0
            >>> leaker.d(0x100) == pwnlib.util.packing.u32(binsh[0x100:0x104])
            leaker failed 0x100
            leaking 0xff
            leaking 0x103
            True
            >>> leaker[0xf0:0x110] == binsh[0xf0:0x110] == leaker.n(0xf0, 0x20)
            leaking 0xf0
            leaking 0xf4
            leaking 0xf8
            leaking 0xfc
            leaking 0x107
            leaking 0x10b
            leaking 0x10f
            True
            >>> import ctypes
            >>> class MyStruct(ctypes.Structure):
            ...     _pack_ = True
            ...     _fields_ = [("a", ctypes.c_char),
            ...                 ("b", ctypes.c_uint32),]
            >>> leaker.field(0x101, MyStruct.b) == leaker.d(0x102)
            True
    """
    def __init__(self, f, search_range = 20, reraise = True):
        self.leak = f
        self.search_range = search_range
        self.reraise = reraise

        # Map of address: byte for all bytes received
        self.cache = {}

    def _do_leak(self, addr):
        """Call the leaker function on address `addr`.  Returns the number of
        bytes leaked.
        """
        try:
            data = self.leak(addr)
        except Exception as e:
            if self.reraise:
                raise
            return 0

        if not data:
            return 0

        for i, b in enumerate(data):
            a = addr + i
            if a in self.cache:
                prev = self.cache[a]
                if prev != b:
                    raise ValueError(
                        "Leaked byte 0x%02x at address 0x%x disagrees with "
                        "previously leaked byte 0x%02x" % (b, prev))
                else:
                    continue

            self.cache[a] = b

        return len(data)

    def rawb(self, addr):
        """raw(addr) -> chr or None

        Returns the byte at `addr` or `None` if it could not be leaked.
        """

        # Negative addresses, wat..?
        if addr < 0:
            return None

        # Try to leak byte if not in cache
        if addr not in self.cache:
            if not self._do_leak(addr):
                # Scan backwards
                for i in xrange(1, self.search_range + 1):
                    # Can't leak below addr 0
                    if addr - i < 0:
                        return None

                    # Stop if we leak enough to cover the byte we're after
                    if self._do_leak(addr - i) > i:
                        break

                else:
                    # Byte could not be leaked :'(
                    self.cache[addr] = None

        return self.cache[addr]

    def raw(self, addr, numb):
        """raw(addr, numb) -> list

        Return a list of `numb` leaked bytes at `addr`.  Bytes that could not be
        leaked are replaced by `None`.
        """

        return map(self.rawb, xrange(addr, addr + numb))

    def struct(self, address, struct):
        """struct(address, struct) => structure object
        Leak an entire structure.
        Arguments:
            address(int):  Addess of structure in memory
            struct(class): A ctypes structure to be instantiated with leaked data
        Return Value:
            An instance of the provided struct class, with the leaked data decoded
        """
        size = sizeof(struct)
        data = self.n(address, size)
        return struct.from_buffer_copy(data) if data else None

    def field(self, address, obj):
        """field(address, field) => a structure field.

        Leak a field from a structure.

        Arguments:
            address(int): Base address to calculate offsets from
            field(obj):   Instance of a ctypes field

        Return Value:
            The type of the return value will be dictated by
            the type of ``field``.
        """
        size   = obj.size
        offset = obj.offset
        data   = self.n(address + offset, size)
        return unpack(data, size*8) if data else None

    def n(self, addr, numb):
        """n(addr, ndx = 0) -> str

        Leak `numb` bytes at `addr`.

        Returns:
            A string with the leaked bytes, or `None` if any are missing

        Examples:

            >>> import string
            >>> data = string.ascii_lowercase
            >>> l = MemLeak(lambda a: data[a:a+4], reraise=False)
            >>> l.n(0,1) == 'a'
            True
            >>> l.n(0,26) == data
            True
            >>> len(l.n(0,26)) == 26
            True
            >>> l.n(0,27) is None
            True

        """
        out = ''
        for i in xrange(numb):
            b = self.rawb(addr + i)
            if b == None:
                return None
            out += b
        return out

    def __getitem__(self, key):
        if isinstance(key, (int, long)):
            return self.rawb(key)
        else:
            if None in (key.start, key.stop):
                raise ValueError("Bot start and stop must be given for leaked range")
            out = ''
            for addr in xrange(key.start, key.stop, key.step or 1):
                b = self.rawb(addr)
                if b == None:
                    return None
                out += b
            return out

    def _int(self, addr, ndx, size):
        addr += ndx * size
        data = self.n(addr, size)

        return unpack(data, 8*size) if data else None

    def b(self, addr, ndx = 0):
        """b(addr, ndx = 0) -> int

        Leak byte at ``((uint8_t*) addr)[ndx]``

        Examples:

            >>> import string
            >>> data = string.ascii_lowercase
            >>> l = MemLeak(lambda a: data[a:a+2], reraise=False)
            >>> l.b(0) == ord('a')
            True
            >>> l.b(25) == ord('z')
            True
            >>> l.b(26) is None
            True
        """
        return self._int(addr, ndx, 1)

    def w(self, addr, ndx = 0):
        """w(addr, ndx = 0) -> int

        Leak word at ``((uint16_t*) addr)[ndx]``

        Examples:

            >>> import string
            >>> data = string.ascii_lowercase
            >>> l = MemLeak(lambda a: data[a:a+4], reraise=False)
            >>> l.w(0) == unpack('ab', 16)
            True
            >>> l.w(24) == unpack('yz', 16)
            True
            >>> l.w(25) is None
            True
        """
        return self._int(addr, ndx, 2)

    def d(self, addr, ndx = 0):
        """d(addr, ndx = 0) -> int

        Leak dword at ``((uint32_t*) addr)[ndx]``

        Examples:

            >>> import string
            >>> data = string.ascii_lowercase
            >>> l = MemLeak(lambda a: data[a:a+8], reraise=False)
            >>> l.d(0) == unpack('abcd', 32)
            True
            >>> l.d(22) == unpack('wxyz', 32)
            True
            >>> l.d(23) is None
            True
        """
        return self._int(addr, ndx, 4)

    def q(self, addr, ndx = 0):
        """q(addr, ndx = 0) -> int

        Leak qword at ``((uint64_t*) addr)[ndx]``

        Examples:

            >>> import string
            >>> data = string.ascii_lowercase
            >>> l = MemLeak(lambda a: data[a:a+16], reraise=False)
            >>> l.q(0) == unpack('abcdefgh', 64)
            True
            >>> l.q(18) == unpack('stuvwxyz', 64)
            True
            >>> l.q(19) is None
            True
        """
        return self._int(addr, ndx, 8)

    def s(self, addr):
        r"""s(addr) -> str

        Leak bytes at `addr` until failure or a nullbyte is found

        Return:
            A string, without a NULL terminator.
            The returned string will be empty if the first byte is
            a NULL terminator, or if the first byte could not be
            retrieved.

        Examples:

            >>> data = "Hello\x00World"
            >>> l = MemLeak(lambda a: data[a:a+4], reraise=False)
            >>> l.s(0) == "Hello"
            True
            >>> l.s(5) == ""
            True
            >>> l.s(6) == "World"
            True
            >>> l.s(999) == ""
            True
        """

        numb = 0
        # Don't worry; there's a cache
        while self.rawb(addr + numb) not in (None, '\x00'):
            numb += 1
        return self.n(addr, numb)

    def _clear(self, addr, ndx, size):
        addr += ndx * size
        data = map(lambda x: self.cache.pop(x, None), range(addr, addr+size))

        if not all(data):
            return None

        return unpack(''.join(data), size*8)

    def clearb(self, addr, ndx = 0):
        """clearb(addr, ndx = 0) -> int

        Clears byte at ``((uint8_t*)addr)[ndx]`` from the cache and
        returns the removed value or `None` if the address was not completely set.

        Examples:

            >>> l = MemLeak(lambda a: None)
            >>> l.cache = {0:'a'}
            >>> l.n(0,1) == 'a'
            True
            >>> l.clearb(0) == unpack('a', 8)
            True
            >>> l.cache
            {}
            >>> l.clearb(0) is None
            True
        """
        return self._clear(addr, ndx, 1)

    def clearw(self, addr, ndx = 0):
        """clearw(addr, ndx = 0) -> int

        Clears word at ``((uint16_t*)addr)[ndx]`` from the cache and
        returns the removed value or `None` if the address was not completely set.

        Examples:

            >>> l = MemLeak(lambda a: None)
            >>> l.cache = {0:'a', 1: 'b'}
            >>> l.n(0, 2) == 'ab'
            True
            >>> l.clearw(0) == unpack('ab', 16)
            True
            >>> l.cache
            {}
        """
        return self._clear(addr, ndx, 2)

    def cleard(self, addr, ndx = 0):
        """cleard(addr, ndx = 0) -> int

        Clears dword at ``((uint32_t*)addr)[ndx]`` from the cache and
        returns the removed value or `None` if the address was not completely set.

        Examples:

            >>> l = MemLeak(lambda a: None)
            >>> l.cache = {0:'a', 1: 'b', 2: 'c', 3: 'd'}
            >>> l.n(0, 4) == 'abcd'
            True
            >>> l.cleard(0) == unpack('abcd', 32)
            True
            >>> l.cache
            {}
        """
        return self._clear(addr, ndx, 4)

    def clearq(self, addr, ndx = 0):
        """clearq(addr, ndx = 0) -> int

        Clears qword at ``((uint64_t*)addr)[ndx]`` from the cache and
        returns the removed value or `None` if the address was not completely set.

        Examples:

            >>> c = MemLeak(lambda addr: '')
            >>> c.cache = {x:'x' for x in range(0x100, 0x108)}
            >>> c.clearq(0x100) == unpack('xxxxxxxx', 64)
            True
            >>> c.cache == {}
            True
        """
        return self._clear(addr, ndx, 8)


    def _set(self, addr, val, ndx, size):
        addr += ndx * size
        for i,b in enumerate(pack(val, size*8)):
            self.cache[addr+i] = b

    def setb(self, addr, val, ndx = 0):
        """Sets byte at ``((uint8_t*)addr)[ndx]`` to `val` in the cache.

        Examples:

            >>> l = MemLeak(lambda x: '')
            >>> l.cache == {}
            True
            >>> l.setb(33, 0x41)
            >>> l.cache == {33: 'A'}
            True
        """
        return self._set(addr, val, ndx, 1)

    def setw(self, addr, val, ndx = 0):
        r"""Sets word at ``((uint16_t*)addr)[ndx]`` to `val` in the cache.

        Examples:

            >>> l = MemLeak(lambda x: '')
            >>> l.cache == {}
            True
            >>> l.setw(33, 0x41)
            >>> l.cache == {33: 'A', 34: '\x00'}
            True
        """
        return self._set(addr, val, ndx, 2)

    def setd(self, addr, val, ndx = 0):
        """Sets dword at ``((uint32_t*)addr)[ndx]`` to `val` in the cache.

        Examples:
            See :meth:`setw`.
        """
        return self._set(addr, val, ndx, 4)

    def setq(self, addr, val, ndx = 0):
        """Sets qword at ``((uint64_t*)addr)[ndx]`` to `val` in the cache.

        Examples:
            See :meth:`setw`.
        """
        return self._set(addr, val, ndx, 8)

    def sets(self, addr, val, null_terminate = True):
        r"""Set known string at `addr`, which will be optionally be null-terminated

        Note that this method is a bit dumb about how it handles the data.
        It will null-terminate the data, but it will not stop at the first null.

        Examples:

            >>> l = MemLeak(lambda x: '')
            >>> l.cache == {}
            True
            >>> l.sets(0, 'H\x00ello')
            >>> l.cache == {0: 'H', 1: '\x00', 2: 'e', 3: 'l', 4: 'l', 5: 'o', 6: '\x00'}
            True
        """
        if null_terminate:
            val += '\x00'

        for i,b in enumerate(val):
            self.cache[addr+i] = b
