"""Module for calculating CRC-sums.

Contains all commonly used crc algorithms. For most implementations it
contains only the core crc algorithm and not e.g. padding schemes.

It is horribly slow, as implements a naive algorithm working direclty on
bit polynomials.

The current algorithm is super-linear and takes about 4 seconds to calculate
the crc32-sum of ``'A'*40000``.

An obvious optimization would be to actually generate some lookup-tables.
"""

from . import fiddling, packing, misc, lists

class _BitPolynom:
    def __init__(self, n):
        if not isinstance(n, (int, long)):
            raise TypeError("Polynomial must be called with an integer or a list")
        if n < 0:
            raise ValueError("Polynomials cannot be negative: %d" % n)
        self.n = n

    def __int__(self):
        return self.n

    def __add__(self, other):
        return _BitPolynom(int(self) ^ int(other))

    def __radd__(self, other):
        return _BitPolynom(int(self) ^ int(other))

    def __sub__(self, other):
        return _BitPolynom(int(self) ^ int(other))

    def __rsub__(self, other):
        return _BitPolynom(int(self) ^ int(other))

    def __xor__(self, other):
        return _BitPolynom(int(self) ^ int(other))

    def __rxor__(self, other):
        return _BitPolynom(int(self) ^ int(other))

    def __or__(self, other):
        return _BitPolynom(int(self) | int(other))

    def __ror__(self, other):
        return _BitPolynom(int(self) | int(other))

    def __and__(self, other):
        return _BitPolynom(int(self) & int(other))

    def __rand__(self, other):
        return _BitPolynom(int(self) & int(other))

    def __mul__(self, other):
        a, b = int(self), int(other)
        if a > b:
            a, b = b, a

        res = 0
        for n in range(a.bit_length()):
            if a & (1 << n):
                res ^= b << n
        return _BitPolynom(res)

    def __rmul__(self, other):
        return self * other

    def __divmod__(self, other):
        other = _BitPolynom(int(other))

        if other == 0:
            raise ZeroDivisionError

        resd = 0
        resm = int(self)

        for n in range(self.degree() - other.degree(), -1, -1):
            if resm & (1 << (n + other.degree())):
                resm ^= int(other) << n
                resd ^= 1 << n
        return (_BitPolynom(resd), _BitPolynom(resm))

    def __rdivmod__(self, other):
        return divmod(_BitPolynom(int(other)), self)

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
        return _BitPolynom(int(self) << int(other))

    def __rlshift__(self, other):
        return _BitPolynom(int(other) << int(self))

    def __rshift__(self, other):
        return _BitPolynom(int(self) >> int(other))

    def __rlshift__(self, other):
        return _BitPolynom(int(other) >> int(self))

    def degree(self):
        return max(0, int(self).bit_length()-1)

    def __repr__(self):
        if int(self) == 0:
            return '0'

        out = []
        for n in range(self.degree(), 0, -1):
            if int(self) & (1 << n):
                out.append("x**%d" % n)
        if int(self) & 1:
            out.append("1")
        return ' + '.join(out)

def generic_crc(data, polynom, width, init, refin, refout, xorout):
    """A generic CRC-sum function.

    This is suitable to use with:
    http://reveng.sourceforge.net/crc-catalogue/all.htm

    Args:
      data(str):    The data to calculate the CRC-sum of. This should either be a string or a list of bits.
      polynom(int): The polynomial to use.
      init(int):    If the CRC-sum was calculated in hardware, then this would b
                    the initial value of the checksum register.
      refin(bool):  Should the input bytes be reflected?
      refout(bool): Should the checksum be reflected?
      xorout(int):  The value to xor the checksum with before outputting

    The "check" value in the document is the CRC-sum of the string "123456789".
"""

    polynom = _BitPolynom(int(polynom)) | (1 << width)
    if polynom.degree() != width:
        raise ValueError("Polynomial is too large for that width")

    init   &= (1 << width)-1
    xorout &= (1 << width)-1

    if isinstance(data, list):
        # refin is not meaningful in this case
        inlen = len(data)
        p = _BitPolynom(int(''.join('1' if v else '0' for v in data), 2))
    elif isinstance(data, str):
        inlen = len(data)*8
        if refin:
            data = fiddling.bitswap(data)
        p = _BitPolynom(packing.unpack(data, 'all', 'big', 'unsigned'))
    p = p << width
    p ^= init << inlen
    p  = p % polynom
    res = p.n
    if refout:
        res = fiddling.bitswap_int(res, width)
    res ^= xorout

    return res

def make_crc(name, polynom, width, init, refin, refout, xorout, extra_doc = ''):
    def inner(data):
        return generic_crc(data, polynom, width, init, refin, refout, xorout)
    inner.func_name = 'crc_' + name
    inner.__name__  = 'crc_' + name

    inner.__doc__   = """Calculates the %s checksum.

    This is simply the generic_crc function with the arguments:
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

def all_crcs():
    """Generates a dictionary of all the known CRC formats from:
    http://reveng.sourceforge.net/crc-catalogue/all.htm"""
    import os, re
    curdir, _ = os.path.split(__file__)
    data = misc.read(os.path.join(curdir, '..', '..', 'data', 'crcsums.txt'))
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
    for ref, l in lists.group(2, data):
        cur = {}
        cur['link'] = 'http://reveng.sourceforge.net/crc-catalogue/all.htm#' + ref
        for key in ['width', 'poly', 'init', 'refin', 'refout', 'xorout', 'check', 'name']:
            cur[key] = fixup(re.findall('%s=(\S+)' % key, l)[0])
        cur['impl'] = make_crc(cur['name'], cur['poly'], cur['width'], cur['init'], cur['refin'], cur['refout'], cur['xorout'], 'See also: ' + cur['link'])
        assert cur['impl']('123456789') == cur['check']
        assert cur['name'] not in out
        out[cur['name']] = cur
    return out

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
