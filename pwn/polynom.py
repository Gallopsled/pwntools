"""Module for fiddling with bitwise representations of polynomials over GF(2).
Or in less fancy talk: I wonder what happens if we replace plus with xor.

This module exports a single class BitPolynom (and some helper functions).

This class represents a polynomial such as x**4 + x + 1.

It can however only represent polynomials with its coefficients in the field
GF(2).

GF(2) is the field containing {0, 1}. For this field, plus and multiplication
works as they normally do, except 1+1=0 (or it is equivalently by doing the
calculation (mod 2)).

We choose a numerical representation of polynomials because it is efficient
(and because it is what the rest of the world uses).

So for instance we represent x**4 + x + 1 as 0b10011.

This has the effect that both plus, minus and xor can be represented by xor.
"""

import pwn

def to_polynom(arg):
    if isinstance(arg, (int, long)):
        return BitPolynom(arg)
    elif isinstance(arg, BitPolynom):
        return arg
    else:
        raise TypeError

def _fix(f):
    @pwn.decoutils.ewraps(f)
    def wrapper(self, other):
        return f(self, to_polynom(other))
    return wrapper

class BitPolynom:
    def __init__(self, n):
        if not isinstance(n, (int, long)):
            raise TypeError("Polynomial must be called with an integer or a list")
        if n < 0:
            raise ValueError("Polynomials cannot be negative: %d" % n)
        self.n = n

    @_fix
    def __add__(self, other):
        return BitPolynom(self.n ^ other.n)

    @_fix
    def __radd__(self, other):
        return BitPolynom(self.n ^ other.n)

    @_fix
    def __sub__(self, other):
        return BitPolynom(self.n ^ other.n)

    @_fix
    def __rsub__(self, other):
        return BitPolynom(self.n ^ other.n)

    @_fix
    def __xor__(self, other):
        return BitPolynom(self.n ^ other.n)

    @_fix
    def __rxor__(self, other):
        return BitPolynom(self.n ^ other.n)

    @_fix
    def __or__(self, other):
        return BitPolynom(self.n | other.n)

    @_fix
    def __ror__(self, other):
        return BitPolynom(self.n | other.n)

    @_fix
    def __and__(self, other):
        return BitPolynom(self.n & other.n)

    @_fix
    def __rand__(self, other):
        return BitPolynom(self.n & other.n)

    @_fix
    def __mul__(self, other):
        a, b = self.n, other.n
        if a > b:
            a, b = b, a

        res = 0
        for n in range(a.bit_length()):
            if a & (1 << n):
                res ^= b << n
        return BitPolynom(res)

    def __rmul__(self, other):
        return self * other

    @_fix
    def __divmod__(self, other):
        if other.n == 0:
            raise ZeroDivisionError

        resd = 0
        resm = self.n

        for n in range(self.degree() - other.degree(), -1, -1):
            if resm & (1 << (n + other.degree())):
                resm ^= other.n << n
                resd ^= 1 << n
        return (BitPolynom(resd), BitPolynom(resm))

    @_fix
    def __rdivmod__(self, other):
        return divmod(other, self)

    def __div__(self, other):
        return divmod(self, other)[0]

    @_fix
    def __rdiv__(self, other):
        return divmod(other, self)[0]

    def __mod__(self, other):
        return divmod(self, other)[1]

    @_fix
    def __rmod__(self, other):
        return divmod(other, self)[1]

    def __eq__(self, other):
        return self.n == other.n

    def __hash__(self):
        return self.n.__hash__()

    @_fix
    def __cmp__(self, other):
        return self.n.__cmp__(other.n)

    @_fix
    def __lshift__(self, other):
        return BitPolynom(self.n << other.n)

    @_fix
    def __rlshift__(self, other):
        return BitPolynom(other.n << self.n)

    @_fix
    def __rshift__(self, other):
        return BitPolynom(self.n >> other.n)

    @_fix
    def __rlshift__(self, other):
        return BitPolynom(other.n >> self.n)

    def degree(self):
        return max(0, self.n.bit_length()-1)

    def __repr__(self):
        if self.n == 0:
            return '0'

        out = []
        for n in range(self.degree(), 0, -1):
            if self.n & (1 << n):
                out.append("x**%d" % n)
        if self.n & 1:
            out.append("1")
        return ' + '.join(out)

def crc(data, polynom, width, init, refin, refout, xorout):
    """A generic CRC-sum function.

    This is suitable to use with:
    http://reveng.sourceforge.net/crc-catalogue/all.htm

    The arguments are:
    - data:    The data to calculate the CRC-sum of. This should either be a string or a list of bits.
    - polynom: The polynomial to use.
    - init:    If the CRC-sum was calculated in hardware, then this would b
               the initial value of the checksum register.
    - refin:   Should the input bytes be reflected?
    - refout:  Should the checksum be reflected?
    - xorout:  The value to xor the checksum with before outputting

    The "check" value in the document is the CRC-sum of the string "123456789".
"""

    polynom = to_polynom(polynom) | (1 << width)
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
            data = pwn.bitflip(data)
        p = BitPolynom(pwn.uintb(data))
    p = p << width
    p ^= init << inlen
    p  = p % polynom
    res = p.n
    if refout:
        res = pwn.bitflip_int(res, width)
    res ^= xorout

    return res

def make_crc(name, polynom, width, init, refin, refout, xorout, extra_doc = ''):
    def inner(data):
        return crc(data, polynom, width, init, refin, refout, xorout)
    inner.func_name = 'crc_' + name
    inner.__name__  = 'crc_' + name

    inner.__doc__   = """Calculates the %s checksum.

    This is simply the generic crc function the arguments:
    polynom = 0x%x
    width   = %d
    init    = 0x%x
    refin   = %s
    refout  = %s
    xorout  = 0x%x

    %s""" % (name, polynom, width, init, refin, refout, xorout, extra_doc)

    return inner

crc32 = make_crc('crc32', 0x04c11db7, 32, 0xffffffff, True, True, 0xffffffff, 'This is the most commonly used CRC sum.')
crc_a = make_crc('crc_a', 0x04c11db7, 32, 0xffffffff, True, True, 0xffffffff, 'This is the CRC sum used for e.g. MIFARE cards.')

def cksum(data):
    l = len(data)
    while l:
        data += p8(l & 0xff)
        l >>= 8
    return crc(data, 0x04c11db7, 32, 0, False, False, 0xffffffff)

@pwn.memoize(use_file = False)
def all_crcs():
    """Generates a dictionary of all the known CRC formats from:
    http://reveng.sourceforge.net/crc-catalogue/all.htm"""
    import os, re
    data = pwn.read(os.path.join(pwn.installpath, 'data', 'crcsums'))
    out = {}
    def fixup(s):
        if s == 'true':
            return True
        elif s == 'false':
            return False
        elif s.startswith('"'):
            assert re.match('"[^"]+"', s)
            return s[1:-1]
        elif s.startswith('0x'):
            assert re.match('0x[0-9a-fA-F]+', s)
            return int(s[2:], 16)
        else:
            assert re.match('[0-9]+', s)
            return int(s, 10)

    data = [l for l in data.strip().split('\n') if l and l[0] != '#']
    assert len(data) % 2 == 0
    for ref, l in pwn.group(2, data):
        cur = {}
        cur['link'] = 'http://reveng.sourceforge.net/crc-catalogue/all.htm#' + ref
        for key in ['width', 'poly', 'init', 'refin', 'refout', 'xorout', 'check', 'name']:
            cur[key] = fixup(re.findall('%s=(\S+)' % key, l)[0])
        cur['impl'] = make_crc(cur['name'], cur['poly'], cur['width'], cur['init'], cur['refin'], cur['refout'], cur['xorout'], 'See also: ' + cur['link'])
        assert cur['impl']('123456789') == cur['check']
        assert cur['name'] not in out
        out[cur['name']] = cur
    return out

@pwn.memoize
def find_crc_function(data, checksum):
    """Finds a specific CRC function from a set of data and its checksum."""
    candidates = []
    for v in all_crcs().values():
        if v['impl'](data) == checksum:
            candidates.append(v)
    if len(candidates) > 1:
        print ("Not enough data to decide which CRC-sum it was. It could be any of:" + ''.join('\n    ' + c['name'] for c in candidates))
    elif len(candidates) == 0:
        print "None of my CRC-sum implementations match this data."
    else:
        return candidates[0]
