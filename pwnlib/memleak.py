from __future__ import absolute_import
from __future__ import division

import ctypes
import functools
import string

import six
from six.moves import range

from pwnlib.context import context
from pwnlib.log import getLogger
from pwnlib.util.packing import pack, _p8lu
from pwnlib.util.packing import unpack

log = getLogger(__name__)

__all__ = ['MemLeak', 'RelativeMemLeak']

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

        >>> import pwnlib
        >>> binsh = pwnlib.util.misc.read('/bin/sh')
        >>> @pwnlib.memleak.MemLeak
        ... def leaker(addr):
        ...     print("leaking 0x%x" % addr)
        ...     return binsh[addr:addr+4]
        >>> leaker.s(0)[:4]
        leaking 0x0
        leaking 0x4
        b'\\x7fELF'
        >>> leaker[:4]
        b'\\x7fELF'
        >>> hex(leaker.d(0))
        '0x464c457f'
        >>> hex(leaker.clearb(1))
        '0x45'
        >>> hex(leaker.d(0))
        leaking 0x1
        '0x464c457f'
        >>> @pwnlib.memleak.MemLeak
        ... def leaker_nonulls(addr):
        ...     print("leaking 0x%x" % addr)
        ...     if addr & 0xff == 0:
        ...         return None
        ...     return binsh[addr:addr+4]
        >>> leaker_nonulls.d(0) is None
        leaking 0x0
        True
        >>> leaker_nonulls[0x100:0x104] == binsh[0x100:0x104]
        leaking 0x100
        leaking 0xff
        leaking 0x103
        True

        >>> memory = {-4+i: c.encode() for i,c in enumerate('wxyzABCDE')}
        >>> def relative_leak(index):
        ...     return memory.get(index, None)
        >>> leak = pwnlib.memleak.MemLeak(relative_leak, relative = True)
        >>> leak[-1:2]
        b'zAB'
    """
    def __init__(self, f, search_range = 20, reraise = True, relative = False):
        self.leak = f
        self.search_range = search_range
        self.reraise = reraise
        self.relative = relative

        # Map of address: byte for all bytes received
        self.cache = {}

        functools.update_wrapper(self, f)

    def __repr__(self):
        return "%s.%s(%r, search_range=%i, reraise=%s)" % (
            self.__class__.__module__,
            self.__class__.__name__,
            self.leak,
            self.search_range,
            self.reraise
        )

    def __call__(self, *a, **kw):
        return self.leak(*a, **kw)

    def struct(self, address, struct):
        """struct(address, struct) => structure object
        Leak an entire structure.
        Arguments:
            address(int):  Addess of structure in memory
            struct(class): A ctypes structure to be instantiated with leaked data
        Return Value:
            An instance of the provided struct class, with the leaked data decoded

        Examples:

            >>> @pwnlib.memleak.MemLeak
            ... def leaker(addr):
            ...     return b"A"
            >>> e = leaker.struct(0, pwnlib.elf.Elf32_Phdr)
            >>> hex(e.p_paddr)
            '0x41414141'

        """
        size = ctypes.sizeof(struct)
        data = self.n(address, size)
        obj = struct.from_buffer_copy(data)
        return obj

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
        if not data:
            return None
        return unpack(data, size*8)

    def field_compare(self, address, obj, expected):
        """field_compare(address, field, expected) ==> bool

        Leak a field from a structure, with an expected value.
        As soon as any mismatch is found, stop leaking the structure.

        Arguments:
            address(int): Base address to calculate offsets from
            field(obj):   Instance of a ctypes field
            expected(int,bytes): Expected value

        Return Value:
            The type of the return value will be dictated by
            the type of ``field``.
        """

        if isinstance(expected, six.integer_types):
            expected = pack(expected, bytes=obj.size)
        elif not isinstance(expected, bytes):
            raise TypeError("Expected value must be an int or bytes")

        assert obj.size == len(expected)

        return self.compare(address + obj.offset, expected)

    def _leak(self, addr, n, recurse=True):
        """_leak(addr, n) => str

        Leak ``n`` consecutive bytes starting at ``addr``.

        Returns:
            A string of length ``n``, or :const:`None`.
        """
        if not self.relative and addr < 0:
            return None

        addresses = [addr+i for i in range(n)]

        for address in addresses:
            # Cache hit
            if address in self.cache:
                continue

            # Cache miss, get the data from the leaker
            data = None
            try:
                data = self.leak(address)
            except Exception as e:
                if self.reraise:
                    raise

            if data:
                for i,byte in enumerate(bytearray(data)):
                    self.cache[address+i] = _p8lu(byte)

            # We could not leak this particular byte, search backwards
            # to see if another request will satisfy it
            elif recurse:
                for i in range(1, self.search_range):
                    data = self._leak(address-i, i+1, False)
                    if address in self.cache:
                        break
                else:
                    return None

        # Ensure everything is in the cache
        if not all(a in self.cache for a in addresses):
            return None

        # Cache is filled, satisfy the request
        return b''.join(self.cache[addr+i] for i in range(n))

    def raw(self, addr, numb):
        """raw(addr, numb) -> list

        Leak `numb` bytes at `addr`"""
        return [self._leak(a, 1) for a in range(addr, addr+numb)]


    def _b(self, addr, ndx, size):
        addr += ndx * size
        data = self._leak(addr, size)

        if not data:
            return None

        return unpack(data, 8*size)

    def b(self, addr, ndx = 0):
        """b(addr, ndx = 0) -> int

        Leak byte at ``((uint8_t*) addr)[ndx]``

        Examples:

            >>> import string
            >>> data = string.ascii_lowercase.encode()
            >>> l = MemLeak(lambda a: data[a:a+2], reraise=False)
            >>> l.b(0) == ord('a')
            True
            >>> l.b(25) == ord('z')
            True
            >>> l.b(26) is None
            True
        """
        return self._b(addr, ndx, 1)

    def w(self, addr, ndx = 0):
        """w(addr, ndx = 0) -> int

        Leak word at ``((uint16_t*) addr)[ndx]``

        Examples:

            >>> import string
            >>> data = string.ascii_lowercase.encode()
            >>> l = MemLeak(lambda a: data[a:a+4], reraise=False)
            >>> l.w(0) == unpack(b'ab', 16)
            True
            >>> l.w(24) == unpack(b'yz', 16)
            True
            >>> l.w(25) is None
            True
        """
        return self._b(addr, ndx, 2)

    def d(self, addr, ndx = 0):
        """d(addr, ndx = 0) -> int

        Leak dword at ``((uint32_t*) addr)[ndx]``

        Examples:

            >>> import string
            >>> data = string.ascii_lowercase.encode()
            >>> l = MemLeak(lambda a: data[a:a+8], reraise=False)
            >>> l.d(0) == unpack(b'abcd', 32)
            True
            >>> l.d(22) == unpack(b'wxyz', 32)
            True
            >>> l.d(23) is None
            True
        """
        return self._b(addr, ndx, 4)

    def q(self, addr, ndx = 0):
        """q(addr, ndx = 0) -> int

        Leak qword at ``((uint64_t*) addr)[ndx]``

        Examples:

            >>> import string
            >>> data = string.ascii_lowercase.encode()
            >>> l = MemLeak(lambda a: data[a:a+16], reraise=False)
            >>> l.q(0) == unpack(b'abcdefgh', 64)
            True
            >>> l.q(18) == unpack(b'stuvwxyz', 64)
            True
            >>> l.q(19) is None
            True
        """
        return self._b(addr, ndx, 8)

    def p(self, addr, ndx = 0):
        """p(addr, ndx = 0) -> int

        Leak a pointer-width value at ``((void**) addr)[ndx]``
        """
        return self._b(addr, ndx, context.bytes)

    def s(self, addr):
        r"""s(addr) -> str

        Leak bytes at `addr` until failure or a nullbyte is found

        Return:
            A string, without a NULL terminator.
            The returned string will be empty if the first byte is
            a NULL terminator, or if the first byte could not be
            retrieved.

        Examples:

            >>> data = b"Hello\x00World"
            >>> l = MemLeak(lambda a: data[a:a+4], reraise=False)
            >>> l.s(0) == b"Hello"
            True
            >>> l.s(5) == b""
            True
            >>> l.s(6) == b"World"
            True
            >>> l.s(999) == b""
            True
        """

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

        Examples:

            >>> import string
            >>> data = string.ascii_lowercase.encode()
            >>> l = MemLeak(lambda a: data[a:a+4], reraise=False)
            >>> l.n(0,1) == b'a'
            True
            >>> l.n(0,26) == data
            True
            >>> len(l.n(0,26)) == 26
            True
            >>> l.n(0,27) is None
            True
        """
        return self._leak(addr, numb) or None


    def _clear(self, addr, ndx, size):
        addr += ndx * size
        data = [self.cache.pop(x, None) for x in range(addr, addr+size)]

        if not all(data):
            return None

        return unpack(b''.join(data), size*8)

    def clearb(self, addr, ndx = 0):
        """clearb(addr, ndx = 0) -> int

        Clears byte at ``((uint8_t*)addr)[ndx]`` from the cache and
        returns the removed value or `None` if the address was not completely set.

        Examples:

            >>> l = MemLeak(lambda a: None)
            >>> l.cache = {0:b'a'}
            >>> l.n(0,1) == b'a'
            True
            >>> l.clearb(0) == unpack(b'a', 8)
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
            >>> l.cache = {0: b'a', 1: b'b'}
            >>> l.n(0, 2) == b'ab'
            True
            >>> l.clearw(0) == unpack(b'ab', 16)
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
            >>> l.cache = {0: b'a', 1: b'b', 2: b'c', 3: b'd'}
            >>> l.n(0, 4) == b'abcd'
            True
            >>> l.cleard(0) == unpack(b'abcd', 32)
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

            >>> c = MemLeak(lambda addr: b'')
            >>> c.cache = {x:b'x' for x in range(0x100, 0x108)}
            >>> c.clearq(0x100) == unpack(b'xxxxxxxx', 64)
            True
            >>> c.cache == {}
            True
        """
        return self._clear(addr, ndx, 8)


    def _set(self, addr, val, ndx, size):
        addr += ndx * size
        for i,b in enumerate(bytearray(pack(val, size*8))):
            self.cache[addr+i] = _p8lu(b)

    def setb(self, addr, val, ndx = 0):
        """Sets byte at ``((uint8_t*)addr)[ndx]`` to `val` in the cache.

        Examples:

            >>> l = MemLeak(lambda x: b'')
            >>> l.cache == {}
            True
            >>> l.setb(33, 0x41)
            >>> l.cache == {33: b'A'}
            True
        """
        return self._set(addr, val, ndx, 1)

    def setw(self, addr, val, ndx = 0):
        r"""Sets word at ``((uint16_t*)addr)[ndx]`` to `val` in the cache.

        Examples:

            >>> l = MemLeak(lambda x: b'')
            >>> l.cache == {}
            True
            >>> l.setw(33, 0x41)
            >>> l.cache == {33: b'A', 34: b'\x00'}
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

            >>> l = MemLeak(lambda x: b'')
            >>> l.cache == {}
            True
            >>> l.sets(0, b'H\x00ello')
            >>> l.cache == {0: b'H', 1: b'\x00', 2: b'e', 3: b'l', 4: b'l', 5: b'o', 6: b'\x00'}
            True
        """
        if null_terminate:
            val += b'\x00'

        for i,b in enumerate(bytearray(val)):
            self.cache[addr+i] = _p8lu(b)

    def __getitem__(self, item):
        if isinstance(item, slice):
            start = item.start or 0
            stop  = item.stop
            step  = item.step
        else:
            start, stop, step = (item, item+1, 1)

        if None in (stop, start):
            log.error("Cannot perform unbounded leaks")

        return self.n(start, stop-start)[::step]

    def compare(self, address, bts):
        for i, byte in enumerate(bytearray(bts)):
            if self.n(address + i, 1) != _p8lu(byte):
                return False
        return True

    @staticmethod
    def NoNulls(function):
        """Wrapper for leak functions such that addresses which contain NULL
        bytes are not leaked.

        This is useful if the address which is used for the leak is read in via
        a string-reading function like ``scanf("%s")`` or smilar.
        """

        @functools.wraps(function, updated=[])
        def null_wrapper(address, *a, **kw):
            if b'\x00' in pack(address):
                log.info('Ignoring leak request for %#x: Contains NULL bytes' % address)
                return None
            return function(address, *a, **kw)

        return MemLeak(null_wrapper)

    @staticmethod
    def NoWhitespace(function):
        """Wrapper for leak functions such that addresses which contain whitespace
        bytes are not leaked.

        This is useful if the address which is used for the leak is read in via
        e.g. ``scanf()``.
        """

        @functools.wraps(function, updated=[])
        def whitespace_wrapper(address, *a, **kw):
            if set(pack(address)) & set(string.whitespace.encode()):
                log.info('Ignoring leak request for %#x: Contains whitespace' % address)
                return None
            return function(address, *a, **kw)

        return MemLeak(whitespace_wrapper)

    @staticmethod
    def NoNewlines(function):
        """Wrapper for leak functions such that addresses which contain newline
        bytes are not leaked.

        This is useful if the address which is used for the leak is provided by
        e.g. ``fgets()``.
        """

        @functools.wraps(function, updated=[])
        def whitespace_wrapper(address, *a, **kw):
            if b'\n' in pack(address):
                log.info('Ignoring leak request for %#x: Contains newlines' % address)
                return None
            return function(address, *a, **kw)

        return MemLeak(whitespace_wrapper)

    @staticmethod
    def String(function):
        """Wrapper for leak functions which leak strings, such that a NULL
        terminator is automaticall added.

        This is useful if the data leaked is printed out as a NULL-terminated
        string, via e.g. ``printf()``.
        """

        @functools.wraps(function, updated=[])
        def string_wrapper(address, *a, **kw):
            result = function(address, *a, **kw)
            if isinstance(result, str) and not isinstance(result, bytes):
                result = result.encode('latin1')
            if isinstance(result, bytes):
                result += b'\x00'
            return result

        return MemLeak(string_wrapper)

    # Aliases for convenience
    u64 = q
    u32 = d
    u16 = w
    u8 = b

    p64 = setq
    p32 = setd
    p16 = setw
    p8 = setb

class RelativeMemLeak(MemLeak):
    def __init__(self, *a, **kw):
        kw.setdefault('relative', True)
        super(RelativeMemLeak, self).__init__(*a, **kw)
