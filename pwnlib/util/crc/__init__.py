"""Module for calculating CRC-sums.

Contains all crc implementations know on the interwebz. For most implementations
it contains only the core crc algorithm and not e.g. padding schemes.

It is horribly slow, as implements a naive algorithm working direclty on
bit polynomials. This class is exposed as `BitPolynom`.

The current algorithm is super-linear and takes about 4 seconds to calculate
the crc32-sum of ``'A'*40000``.

An obvious optimization would be to actually generate some lookup-tables.
"""
from __future__ import absolute_import

import sys
import types

from pwnlib.util import fiddling
from pwnlib.util import packing
from pwnlib.util import safeeval
from pwnlib.util.crc import known


class BitPolynom(object):
    """Class for representing GF(2)[X], i.e. the field of polynomials over
    GF(2).

    In practice the polynomials are represented as numbers such that `x**n`
    corresponds to `1 << n`. In this representation calculations are easy: Just
    do everything as normal, but forget about everything the carries.

    Addition becomes xor and multiplication becomes carry-less multiplication.

    Examples:

        >>> p1 = BitPolynom("x**3 + x + 1")
        >>> p1
        BitPolynom('x**3 + x + 1')
        >>> int(p1)
        11
        >>> p1 == BitPolynom(11)
        True
        >>> p2 = BitPolynom("x**2 + x + 1")
        >>> p1 + p2
        BitPolynom('x**3 + x**2')
        >>> p1 * p2
        BitPolynom('x**5 + x**4 + 1')
        >>> p1 / p2
        BitPolynom('x + 1')
        >>> p1 % p2
        BitPolynom('x')
        >>> d, r = divmod(p1, p2)
        >>> d * p2 + r == p1
        True
        >>> BitPolynom(-1)
        Traceback (most recent call last):
            ...
        ValueError: Polynomials cannot be negative: -1
        >>> BitPolynom('y')
        Traceback (most recent call last):
            ...
        ValueError: Not a valid polynomial: y
    """


    def __init__(self, n):
        if isinstance(n, (str, unicode)):
            self.n = 0
            x = BitPolynom(2)
            try:
                for p in n.split('+'):
                    k = safeeval.values(p.strip(), {'x': x, 'X': x})
                    assert isinstance(k, (BitPolynom, int, long))
                    assert k >= 0
                    self.n ^= int(k)
            except (ValueError, NameError, AssertionError):
                raise ValueError("Not a valid polynomial: %s" % n)
        elif isinstance(n, (int, long)):
            if n >= 0:
                self.n = n
            else:
                raise ValueError("Polynomials cannot be negative: %d" % n)
        else:
            raise TypeError("Polynomial must be called with a string or integer")

    def __int__(self):
        return self.n

    def __add__(self, other):
        return BitPolynom(int(self) ^ int(other))

    def __radd__(self, other):
        return BitPolynom(int(self) ^ int(other))

    def __sub__(self, other):
        return BitPolynom(int(self) ^ int(other))

    def __rsub__(self, other):
        return BitPolynom(int(self) ^ int(other))

    def __xor__(self, other):
        return BitPolynom(int(self) ^ int(other))

    def __rxor__(self, other):
        return BitPolynom(int(self) ^ int(other))

    def __or__(self, other):
        return BitPolynom(int(self) | int(other))

    def __ror__(self, other):
        return BitPolynom(int(self) | int(other))

    def __and__(self, other):
        return BitPolynom(int(self) & int(other))

    def __rand__(self, other):
        return BitPolynom(int(self) & int(other))

    def __mul__(self, other):
        a, b = int(self), int(other)
        if a > b:
            a, b = b, a

        res = 0
        for n in range(a.bit_length()):
            if a & (1 << n):
                res ^= b << n
        return BitPolynom(res)

    def __rmul__(self, other):
        return self * other

    def __divmod__(self, other):
        other = BitPolynom(int(other))

        if other == 0:
            raise ZeroDivisionError

        resd = 0
        resm = int(self)

        for n in range(self.degree() - other.degree(), -1, -1):
            if resm & (1 << (n + other.degree())):
                resm ^= int(other) << n
                resd ^= 1 << n
        return (BitPolynom(resd), BitPolynom(resm))

    def __rdivmod__(self, other):
        return divmod(BitPolynom(int(other)), self)

    def __div__(self, other):
        return divmod(self, other)[0]

    def __rdiv__(self, other):
        return divmod(other, self)[0]

    def __mod__(self, other):
        return divmod(self, other)[1]

    def __rmod__(self, other):
        return divmod(other, self)[1]

    def __eq__(self, other):
        return int(self) == int(other)

    def __hash__(self):
        return int(self).__hash__()

    def __cmp__(self, other):
        return int(self).__cmp__(int(other))

    def __lshift__(self, other):
        return BitPolynom(int(self) << int(other))

    def __rlshift__(self, other):
        return BitPolynom(int(other) << int(self))

    def __rshift__(self, other):
        return BitPolynom(int(self) >> int(other))

    def __rrshift__(self, other):
        return BitPolynom(int(other) >> int(self))

    def __pow__(self, other):
        r = BitPolynom(1)
        for _ in range(other):
            r *= self
        return r

    def degree(self):
        """Returns the degree of the polynomial.

        Examples:

            >>> BitPolynom(0).degree()
            0
            >>> BitPolynom(1).degree()
            0
            >>> BitPolynom(2).degree()
            1
            >>> BitPolynom(7).degree()
            2
            >>> BitPolynom((1 << 10) - 1).degree()
            9
            >>> BitPolynom(1 << 10).degree()
            10
        """
        return max(0, int(self).bit_length()-1)

    def __repr__(self):
        if int(self) == 0:
            return '0'

        out = []
        for n in range(self.degree(), 1, -1):
            if int(self) & (1 << n):
                out.append("x**%d" % n)
        if int(self) & 2:
            out.append("x")
        if int(self) & 1:
            out.append("1")
        return 'BitPolynom(%r)' % ' + '.join(out)

class Module(types.ModuleType):
    def __init__(self):
        super(Module, self).__init__(__name__)
        self._cached_crcs = None
        self.BitPolynom = BitPolynom
        self.__dict__.update({
            '__file__'    : __file__,
            '__package__' : __package__,
        })

    def __getattr__(self, attr):
        crcs = known.all_crcs

        if attr == '__all__':
            return ['BitPolynom', 'generic_crc', 'cksum', 'find_crc_function'] + sorted(crcs.keys())

        info = crcs.get(attr, None)
        if not info:
            raise AttributeError("'module' object has no attribute %r" % attr)

        func = self._make_crc(info['name'], info['poly'], info['width'], info['init'], info['refin'], info['refout'], info['xorout'], info['check'], 'See also: ' + info['link'])

        setattr(self, attr, func)

        return func

    def __dir__(self):
        return self.__all__

    @staticmethod
    def generic_crc(data, polynom, width, init, refin, refout, xorout):
        """A generic CRC-sum function.

        This is suitable to use with:
        http://reveng.sourceforge.net/crc-catalogue/all.htm

        The "check" value in the document is the CRC-sum of the string "123456789".

        Arguments:
            data(str):    The data to calculate the CRC-sum of. This should either be a string or a list of bits.
            polynom(int): The polynomial to use.
            init(int):    If the CRC-sum was calculated in hardware, then this would b
                        the initial value of the checksum register.
            refin(bool):  Should the input bytes be reflected?
            refout(bool): Should the checksum be reflected?
            xorout(int):  The value to xor the checksum with before outputting
        """

        polynom = BitPolynom(int(polynom)) | (1 << width)
        if polynom.degree() != width:
            raise ValueError("Polynomial is too large for that width")

        init   &= (1 << width)-1
        xorout &= (1 << width)-1

        if isinstance(data, list):
            # refin is not meaningful in this case
            inlen = len(data)
            p = BitPolynom(int(''.join('1' if v else '0' for v in data), 2))
        elif isinstance(data, str):
            inlen = len(data)*8
            if refin:
                data = fiddling.bitswap(data)
            p = BitPolynom(packing.unpack(data, 'all', endian='big', sign=False))
        p = p << width
        p ^= init << inlen
        p  = p % polynom
        res = p.n
        if refout:
            res = fiddling.bitswap_int(res, width)
        res ^= xorout

        return res

    @staticmethod
    def _make_crc(name, polynom, width, init, refin, refout, xorout, check, extra_doc = ''):
        def inner(data):
            return crc.generic_crc(data, polynom, width, init, refin, refout, xorout)
        inner.func_name = 'crc_' + name
        inner.__name__  = 'crc_' + name

        inner.__doc__   = """%s(data) -> int

        Calculates the %s checksum.

        This is simply the :func:`generic_crc` with these frozen arguments:

        * polynom = 0x%x
        * width   = %d
        * init    = 0x%x
        * refin   = %s
        * refout  = %s
        * xorout  = 0x%x

        %s

        Arguments:
            data(str): The data to checksum.

        Example:
            >>> print %s('123456789')
            %d
    """ % (name, name, polynom, width, init, refin, refout, xorout, extra_doc, name, check)

        return inner

    @staticmethod
    def cksum(data):
        """cksum(data) -> int

        Calculates the same checksum as returned by the UNIX-tool ``cksum``.

        Arguments:
            data(str): The data to checksum.

        Example:
            >>> print cksum('123456789')
            930766865
        """

        l = len(data)
        data += packing.pack(l, 'all', endian='little', sign=False)
        return crc.crc_32_posix(data)

    @staticmethod
    def find_crc_function(data, checksum):
        """Finds all known CRC functions that hashes a piece of data into a specific
        checksum. It does this by trying all known CRC functions one after the other.

        Arguments:
            data(str): Data for which the checksum is known.

        Example:
            >>> find_crc_function('test', 46197)
            [<function crc_crc_16_dnp at ...>]
        """
        candidates = []
        for v in known.all_crcs.keys():
            func = getattr(crc, v)
            if func(data) == checksum:
                candidates.append(func)
        return candidates


tether = sys.modules[__name__]
crc = sys.modules[__name__] = Module()
crc.__doc__ = tether.__doc__
