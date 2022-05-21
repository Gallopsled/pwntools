# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division

import base64
import binascii
import random
import re
import os
import six
import string

from six import BytesIO
from six.moves import range

from pwnlib.context import context
from pwnlib.log import getLogger
from pwnlib.term import text
from pwnlib.util import lists
from pwnlib.util import packing
from pwnlib.util.cyclic import cyclic
from pwnlib.util.cyclic import de_bruijn
from pwnlib.util.cyclic import cyclic_find

log = getLogger(__name__)

def unhex(s):
    r"""unhex(s) -> str

    Hex-decodes a string.

    Example:

        >>> unhex("74657374")
        b'test'
        >>> unhex("F\n")
        b'\x0f'
    """
    s = s.strip()
    if len(s) % 2 != 0:
        s = '0' + s
    return binascii.unhexlify(s)

def enhex(x):
    """enhex(x) -> str

    Hex-encodes a string.

    Example:

        >>> enhex(b"test")
        '74657374'
    """
    x = binascii.hexlify(x)
    if not hasattr(x, 'encode'):
        x = x.decode('ascii')
    return x

def urlencode(s):
    """urlencode(s) -> str

    URL-encodes a string.

    Example:

        >>> urlencode("test")
        '%74%65%73%74'
    """
    return ''.join(['%%%02x' % ord(c) for c in s])

def urldecode(s, ignore_invalid = False):
    """urldecode(s, ignore_invalid = False) -> str

    URL-decodes a string.

    Example:

        >>> urldecode("test%20%41")
        'test A'
        >>> urldecode("%qq")
        Traceback (most recent call last):
        ...
        ValueError: Invalid input to urldecode
        >>> urldecode("%qq", ignore_invalid = True)
        '%qq'
    """
    res = ''
    n = 0
    while n < len(s):
        if s[n] != '%':
            res += s[n]
            n += 1
        else:
            cur = s[n+1:n+3]
            if re.match('[0-9a-fA-F]{2}', cur):
                res += chr(int(cur, 16))
                n += 3
            elif ignore_invalid:
                res += '%'
                n += 1
            else:
                raise ValueError("Invalid input to urldecode")
    return res

def bits(s, endian = 'big', zero = 0, one = 1):
    """bits(s, endian = 'big', zero = 0, one = 1) -> list

    Converts the argument into a list of bits.

    Arguments:
        s: A string or number to be converted into bits.
        endian (str): The binary endian, default 'big'.
        zero: The representing a 0-bit.
        one: The representing a 1-bit.

    Returns:
        A list consisting of the values specified in `zero` and `one`.

    Examples:

        >>> bits(511, zero = "+", one = "-")
        ['+', '+', '+', '+', '+', '+', '+', '-', '-', '-', '-', '-', '-', '-', '-', '-']
        >>> sum(bits(b"test"))
        17
        >>> bits(0)
        [0, 0, 0, 0, 0, 0, 0, 0]
    """

    if endian not in ['little', 'big']:
        raise ValueError("bits(): 'endian' must be either 'little' or 'big'")
    else:
        little = endian == 'little'

    out = []
    if isinstance(s, bytes):
        for b in bytearray(s):
            byte = []
            for _ in range(8):
                byte.append(one if b & 1 else zero)
                b >>= 1
            if little:
                out += byte
            else:
                out += byte[::-1]
    elif isinstance(s, six.integer_types):
        if s < 0:
            s = s & ((1<<context.bits)-1)
        if s == 0:
            out.append(zero)
        while s:
            bit, s = one if s & 1 else zero, s >> 1
            out.append(bit)
        while len(out) % 8:
            out.append(zero)
        if not little:
            out = out[::-1]
    else:
        raise ValueError("bits(): 's' must be either a string or a number")

    return out

def bits_str(s, endian = 'big', zero = '0', one = '1'):
    """bits_str(s, endian = 'big', zero = '0', one = '1') -> str

    A wrapper around :func:`bits`, which converts the output into a string.

    Examples:

       >>> bits_str(511)
       '0000000111111111'
       >>> bits_str(b"bits_str", endian = "little")
       '0100011010010110001011101100111011111010110011100010111001001110'
    """
    return ''.join(bits(s, endian, zero, one))

def unbits(s, endian = 'big'):
    """unbits(s, endian = 'big') -> str

    Converts an iterable of bits into a string.

    Arguments:
       s: Iterable of bits
       endian (str):  The string "little" or "big", which specifies the bits endianness.

    Returns:
       A string of the decoded bits.

    Example:
       >>> unbits([1])
       b'\\x80'
       >>> unbits([1], endian = 'little')
       b'\\x01'
       >>> unbits(bits(b'hello'), endian = 'little')
       b'\\x16\\xa666\\xf6'
    """
    if endian == 'little':
        u = lambda s: packing._p8lu(int(s[::-1], 2))
    elif endian == 'big':
        u = lambda s: packing._p8lu(int(s, 2))
    else:
        raise ValueError("unbits(): 'endian' must be either 'little' or 'big'")

    out = b''
    cur = b''

    for c in s:
        if c in ['1', 1, True]:
            cur += b'1'
        elif c in ['0', 0, False]:
            cur += b'0'
        else:
            raise ValueError("unbits(): cannot decode the value %r into a bit" % c)

        if len(cur) == 8:
            out += u(cur)
            cur = b''
    if cur:
        out += u(cur.ljust(8, b'0'))

    return out


def bitswap(s):
    """bitswap(s) -> str

    Reverses the bits in every byte of a given string.

    Example:
        >>> bitswap(b"1234")
        b'\\x8cL\\xcc,'
    """

    out = []

    for c in s:
        out.append(unbits(bits_str(c)[::-1]))

    return b''.join(out)

def bitswap_int(n, width):
    """bitswap_int(n) -> int

    Reverses the bits of a numbers and returns the result as a new number.

    Arguments:
        n (int): The number to swap.
        width (int): The width of the integer

    Examples:
        >>> hex(bitswap_int(0x1234, 8))
        '0x2c'
        >>> hex(bitswap_int(0x1234, 16))
        '0x2c48'
        >>> hex(bitswap_int(0x1234, 24))
        '0x2c4800'
        >>> hex(bitswap_int(0x1234, 25))
        '0x589000'
    """
    # Make n fit inside the width
    n &= (1 << width) - 1

    # Convert into bits
    s = bits_str(n, endian = 'little').ljust(width, '0')[:width]

    # Convert back
    return int(s, 2)


def b64e(s):
    """b64e(s) -> str

    Base64 encodes a string

    Example:

       >>> b64e(b"test")
       'dGVzdA=='
       """
    x = base64.b64encode(s)
    if not hasattr(x, 'encode'):
        x = x.decode('ascii')
    return x

def b64d(s):
    """b64d(s) -> str

    Base64 decodes a string

    Example:

       >>> b64d('dGVzdA==')
       b'test'
    """
    return base64.b64decode(s)

# misc binary functions
def xor(*args, **kwargs):
    """xor(*args, cut = 'max') -> str

    Flattens its arguments using :func:`pwnlib.util.packing.flat` and
    then xors them together. If the end of a string is reached, it wraps
    around in the string.

    Arguments:
       args: The arguments to be xor'ed together.
       cut: How long a string should be returned.
            Can be either 'min'/'max'/'left'/'right' or a number.

    Returns:
       The string of the arguments xor'ed together.

    Example:
       >>> xor(b'lol', b'hello', 42)
       b'. ***'
    """

    cut = kwargs.pop('cut', 'max')

    if kwargs != {}:
        raise TypeError("xor() got an unexpected keyword argument '%s'" % kwargs.pop()[0])

    if len(args) == 0:
        raise ValueError("Must have something to xor")

    strs = [packing.flat(s, word_size = 8, sign = False, endianness = 'little') for s in args]
    strs = [bytearray(s) for s in strs if s]

    if strs == []:
        return b''

    if isinstance(cut, six.integer_types):
        cut = cut
    elif cut == 'left':
        cut = len(strs[0])
    elif cut == 'right':
        cut = len(strs[-1])
    elif cut == 'min':
        cut = min(len(s) for s in strs)
    elif cut == 'max':
        cut = max(len(s) for s in strs)
    else:
        raise ValueError("Not a valid argument for 'cut'")

    def get(n):
        rv = 0
        for s in strs: rv ^= s[n%len(s)]
        return packing._p8lu(rv)

    return b''.join(map(get, range(cut)))

def xor_pair(data, avoid = b'\x00\n'):
    """xor_pair(data, avoid = '\\x00\\n') -> None or (str, str)

    Finds two strings that will xor into a given string, while only
    using a given alphabet.

    Arguments:
        data (str): The desired string.
        avoid: The list of disallowed characters. Defaults to nulls and newlines.

    Returns:
        Two strings which will xor to the given string. If no such two strings exist, then None is returned.

    Example:

        >>> xor_pair(b"test")
        (b'\\x01\\x01\\x01\\x01', b'udru')
    """

    if isinstance(data, six.integer_types):
        data = packing.pack(data)

    if not isinstance(avoid, (bytes, bytearray)):
        avoid = avoid.encode('utf-8')

    avoid = bytearray(avoid)
    alphabet = list(packing._p8lu(n) for n in range(256) if n not in avoid)

    res1 = b''
    res2 = b''

    for c1 in bytearray(data):
        if context.randomize:
            random.shuffle(alphabet)
        for c2 in alphabet:
            c3 = packing._p8lu(c1 ^ packing.u8(c2))
            if c3 in alphabet:
                res1 += c2
                res2 += c3
                break
        else:
            return None

    return res1, res2

def xor_key(data, avoid=b'\x00\n', size=None):
    r"""xor_key(data, size=None, avoid='\x00\n') -> None or (int, str)

    Finds a ``size``-width value that can be XORed with a string
    to produce ``data``, while neither the XOR value or XOR string
    contain any bytes in ``avoid``.

    Arguments:
        data (str): The desired string.
        avoid: The list of disallowed characters. Defaults to nulls and newlines.
        size (int): Size of the desired output value, default is word size.

    Returns:
        A tuple containing two strings; the XOR key and the XOR string.
        If no such pair exists, None is returned.

    Example:

        >>> xor_key(b"Hello, world")
        (b'\x01\x01\x01\x01', b'Idmmn-!vnsme')
    """
    size = size or context.bytes

    if len(data) % size:
        log.error("Data must be padded to size for xor_key")

    words    = lists.group(size, data)
    columns  = [b''] * size
    for word in words:
        for i,byte in enumerate(bytearray(word)):
            columns[i] += bytearray((byte,))

    avoid = bytearray(avoid)
    alphabet = bytearray(n for n in range(256) if n not in avoid)

    result = b''

    for column in columns:
        if context.randomize:
            random.shuffle(alphabet)
        for c2 in alphabet:
            if all(c^c2 in alphabet for c in column):
                result += packing._p8lu(c2)
                break
        else:
            return None

    return result, xor(data, result)

def randoms(count, alphabet = string.ascii_lowercase):
    """randoms(count, alphabet = string.ascii_lowercase) -> str

    Returns a random string of a given length using only the specified alphabet.

    Arguments:
        count (int): The length of the desired string.
        alphabet: The alphabet of allowed characters. Defaults to all lowercase characters.

    Returns:
        A random string.

    Example:

        >>> randoms(10) #doctest: +SKIP
        'evafjilupm'
    """

    return ''.join(random.choice(alphabet) for _ in range(count))


def rol(n, k, word_size = None):
    """Returns a rotation by `k` of `n`.

    When `n` is a number, then means ``((n << k) | (n >> (word_size - k)))`` truncated to `word_size` bits.

    When `n` is a list, tuple or string, this is ``n[k % len(n):] + n[:k % len(n)]``.

    Arguments:
        n: The value to rotate.
        k(int): The rotation amount. Can be a positive or negative number.
        word_size(int): If `n` is a number, then this is the assumed bitsize of `n`.  Defaults to :data:`pwnlib.context.word_size` if `None` .

    Example:

        >>> rol('abcdefg', 2)
        'cdefgab'
        >>> rol('abcdefg', -2)
        'fgabcde'
        >>> hex(rol(0x86, 3, 8))
        '0x34'
        >>> hex(rol(0x86, -3, 8))
        '0xd0'
    """

    word_size = word_size or context.word_size

    if not isinstance(word_size, six.integer_types) or word_size <= 0:
        raise ValueError("rol(): 'word_size' must be a strictly positive integer")

    if not isinstance(k, six.integer_types):
        raise ValueError("rol(): 'k' must be an integer")

    if isinstance(n, (bytes, six.text_type, list, tuple)):
        return n[k % len(n):] + n[:k % len(n)]
    elif isinstance(n, six.integer_types):
        k = k % word_size
        n = (n << k) | (n >> (word_size - k))
        n &= (1 << word_size) - 1

        return n
    else:
        raise ValueError("rol(): 'n' must be an integer, string, list or tuple")

def ror(n, k, word_size = None):
    """A simple wrapper around :func:`rol`, which negates the values of `k`."""

    return rol(n, -k, word_size)

def naf(n):
    """naf(int) -> int generator

    Returns a generator for the non-adjacent form (NAF[1]) of a number, `n`.  If
    `naf(n)` generates `z_0, z_1, ...`, then `n == z_0 + z_1 * 2 + z_2 * 2**2,
    ...`.

    [1] https://en.wikipedia.org/wiki/Non-adjacent_form

    Example:

      >>> n = 45
      >>> m = 0
      >>> x = 1
      >>> for z in naf(n):
      ...     m += x * z
      ...     x *= 2
      >>> n == m
      True

    """
    while n:
        z = 2 - n % 4 if n & 1 else 0
        n = (n - z) // 2
        yield z

def isprint(c):
    """isprint(c) -> bool

    Return True if a character is printable"""
    if isinstance(c, six.text_type):
        c = ord(c)
    t = bytearray(string.ascii_letters + string.digits + string.punctuation + ' ', 'ascii')
    return c in t


def hexii(s, width = 16, skip = True):
    """hexii(s, width = 16, skip = True) -> str

    Return a HEXII-dump of a string.

    Arguments:
        s(str): The string to dump
        width(int): The number of characters per line
        skip(bool): Should repeated lines be replaced by a "*"

    Returns:
        A HEXII-dump in the form of a string.
    """

    return hexdump(s, width, skip, True)

def _hexiichar(c):
    HEXII = bytearray((string.punctuation + string.digits + string.ascii_letters).encode())
    if c in HEXII:
        return ".%c " % c
    elif c == 0:
        return "   "
    elif c == 0xff:
        return "## "
    else:
        return "%02x " % c

default_style = {
    'marker':       text.gray if text.has_gray else text.blue,
    'nonprintable': text.gray if text.has_gray else text.blue,
    '00':           text.red,
    '0a':           text.red,
    'ff':           text.green,
}

cyclic_pregen = b''
de_bruijn_gen = de_bruijn()

def sequential_lines(a,b):
    return (a+b) in cyclic_pregen

def update_cyclic_pregenerated(size):
    global cyclic_pregen
    while size > len(cyclic_pregen):
        cyclic_pregen += packing._p8lu(next(de_bruijn_gen))

def hexdump_iter(fd, width=16, skip=True, hexii=False, begin=0, style=None,
                 highlight=None, cyclic=False, groupsize=4, total=True):
    r"""hexdump_iter(s, width = 16, skip = True, hexii = False, begin = 0, style = None,
                    highlight = None, cyclic = False, groupsize=4, total = True) -> str generator

    Return a hexdump-dump of a string as a generator of lines.  Unless you have
    massive amounts of data you probably want to use :meth:`hexdump`.

    Arguments:
        fd(file): File object to dump.  Use :meth:`StringIO.StringIO` or :meth:`hexdump` to dump a string.
        width(int): The number of characters per line
        groupsize(int): The number of characters per group
        skip(bool): Set to True, if repeated lines should be replaced by a "*"
        hexii(bool): Set to True, if a hexii-dump should be returned instead of a hexdump.
        begin(int):  Offset of the first byte to print in the left column
        style(dict): Color scheme to use.
        highlight(iterable): Byte values to highlight.
        cyclic(bool): Attempt to skip consecutive, unmodified cyclic lines
        total(bool): Set to True, if total bytes should be printed

    Returns:
        A generator producing the hexdump-dump one line at a time.

    Example:

        >>> tmp = tempfile.NamedTemporaryFile()
        >>> _ = tmp.write(b'XXXXHELLO, WORLD')
        >>> tmp.flush()
        >>> _ = tmp.seek(4)
        >>> print('\n'.join(hexdump_iter(tmp)))
        00000000  48 45 4c 4c  4f 2c 20 57  4f 52 4c 44               │HELL│O, W│ORLD│
        0000000c

        >>> t = tube()
        >>> t.unrecv(b'I know kung fu')
        >>> print('\n'.join(hexdump_iter(t)))
        00000000  49 20 6b 6e  6f 77 20 6b  75 6e 67 20  66 75        │I kn│ow k│ung │fu│
        0000000e
    """
    style     = style or {}
    highlight = highlight or []

    if groupsize < 1:
        groupsize = width

    for b in highlight:
        if isinstance(b, str):
            b = ord(b)
        style['%02x' % b] = text.white_on_red
    _style = style
    style = default_style.copy()
    style.update(_style)

    skipping    = False
    lines       = []
    last_unique = ''
    byte_width  = len('00 ')
    spacer      = ' '
    marker      = (style.get('marker') or (lambda s:s))('│')

    if not hexii:
        def style_byte(by):
            hbyte = '%02x' % by
            b = packing._p8lu(by)
            abyte = chr(by) if isprint(b) else '·'
            if hbyte in style:
                st = style[hbyte]
            elif isprint(b):
                st = style.get('printable')
            else:
                st = style.get('nonprintable')
            if st:
                hbyte = st(hbyte)
                abyte = st(abyte)
            return hbyte, abyte
        cache = [style_byte(b) for b in range(256)]

    numb = 0
    while True:
        offset = begin + numb

        # If a tube is passed in as fd, it will raise EOFError when it runs
        # out of data, unlike a file or StringIO object, which return an empty
        # string.
        try:
            chunk = fd.read(width)
        except EOFError:
            chunk = b''

        # We have run out of data, exit the loop
        if chunk == b'':
            break

        # Advance the cursor by the number of bytes we actually read
        numb += len(chunk)

        # Update the cyclic pattern in case
        if cyclic:
            update_cyclic_pregenerated(numb)

        # If this chunk is the same as the last unique chunk,
        # use a '*' instead.
        if skip and last_unique:
            same_as_last_line = (last_unique == chunk)
            lines_are_sequential = (cyclic and sequential_lines(last_unique, chunk))
            last_unique = chunk

            if same_as_last_line or lines_are_sequential:

                # If we have not already printed a "*", do so
                if not skipping:
                    yield '*'
                    skipping = True

                # Move on to the next chunk
                continue

        # Chunk is unique, no longer skipping
        skipping = False
        last_unique = chunk

        # Generate contents for line
        hexbytes = ''
        printable = ''
        color_chars = 0
        abyte = abyte_previous = ''
        for i, b in enumerate(bytearray(chunk)):
            if not hexii:
                abyte_previous = abyte
                hbyte, abyte = cache[b]
                color_chars += len(hbyte) - 2
            else:
                hbyte, abyte = _hexiichar(b), ''

            if (i + 1) % groupsize == 0 and i < width - 1:
                hbyte += spacer
                abyte_previous += abyte
                abyte = marker

            hexbytes += hbyte + ' '
            printable += abyte_previous

        if abyte != marker:
            printable += abyte

        dividers_per_line = (width // groupsize)
        if width % groupsize == 0:
            dividers_per_line -= 1

        if hexii:
            line_fmt = '%%(offset)08x  %%(hexbytes)-%is│' % (width*byte_width)
        else:
            line_fmt = '%%(offset)08x  %%(hexbytes)-%is │%%(printable)s│' % (
                 (width * byte_width)
                + color_chars
                + dividers_per_line )

        line = line_fmt % {'offset': offset, 'hexbytes': hexbytes, 'printable': printable}
        yield line

    if total:
        line = "%08x" % (begin + numb)
        yield line

def hexdump(s, width=16, skip=True, hexii=False, begin=0, style=None,
            highlight=None, cyclic=False, groupsize=4, total=True):
    r"""hexdump(s, width = 16, skip = True, hexii = False, begin = 0, style = None,
                highlight = None, cyclic = False, groupsize=4, total = True) -> str

    Return a hexdump-dump of a string.

    Arguments:
        s(str): The data to hexdump.
        width(int): The number of characters per line
        groupsize(int): The number of characters per group
        skip(bool): Set to True, if repeated lines should be replaced by a "*"
        hexii(bool): Set to True, if a hexii-dump should be returned instead of a hexdump.
        begin(int):  Offset of the first byte to print in the left column
        style(dict): Color scheme to use.
        highlight(iterable): Byte values to highlight.
        cyclic(bool): Attempt to skip consecutive, unmodified cyclic lines
        total(bool): Set to True, if total bytes should be printed

    Returns:
        A hexdump-dump in the form of a string.

    Examples:

        >>> print(hexdump(b"abc"))
        00000000  61 62 63                                            │abc│
        00000003

        >>> print(hexdump(b'A'*32))
        00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
        *
        00000020

        >>> print(hexdump(b'A'*32, width=8))
        00000000  41 41 41 41  41 41 41 41  │AAAA│AAAA│
        *
        00000020

        >>> print(hexdump(cyclic(32), width=8, begin=0xdead0000, hexii=True))
        dead0000  .a  .a  .a  .a   .b  .a  .a  .a  │
        dead0008  .c  .a  .a  .a   .d  .a  .a  .a  │
        dead0010  .e  .a  .a  .a   .f  .a  .a  .a  │
        dead0018  .g  .a  .a  .a   .h  .a  .a  .a  │
        dead0020

        >>> print(hexdump(bytearray(range(256))))
        00000000  00 01 02 03  04 05 06 07  08 09 0a 0b  0c 0d 0e 0f  │····│····│····│····│
        00000010  10 11 12 13  14 15 16 17  18 19 1a 1b  1c 1d 1e 1f  │····│····│····│····│
        00000020  20 21 22 23  24 25 26 27  28 29 2a 2b  2c 2d 2e 2f  │ !"#│$%&'│()*+│,-./│
        00000030  30 31 32 33  34 35 36 37  38 39 3a 3b  3c 3d 3e 3f  │0123│4567│89:;│<=>?│
        00000040  40 41 42 43  44 45 46 47  48 49 4a 4b  4c 4d 4e 4f  │@ABC│DEFG│HIJK│LMNO│
        00000050  50 51 52 53  54 55 56 57  58 59 5a 5b  5c 5d 5e 5f  │PQRS│TUVW│XYZ[│\]^_│
        00000060  60 61 62 63  64 65 66 67  68 69 6a 6b  6c 6d 6e 6f  │`abc│defg│hijk│lmno│
        00000070  70 71 72 73  74 75 76 77  78 79 7a 7b  7c 7d 7e 7f  │pqrs│tuvw│xyz{│|}~·│
        00000080  80 81 82 83  84 85 86 87  88 89 8a 8b  8c 8d 8e 8f  │····│····│····│····│
        00000090  90 91 92 93  94 95 96 97  98 99 9a 9b  9c 9d 9e 9f  │····│····│····│····│
        000000a0  a0 a1 a2 a3  a4 a5 a6 a7  a8 a9 aa ab  ac ad ae af  │····│····│····│····│
        000000b0  b0 b1 b2 b3  b4 b5 b6 b7  b8 b9 ba bb  bc bd be bf  │····│····│····│····│
        000000c0  c0 c1 c2 c3  c4 c5 c6 c7  c8 c9 ca cb  cc cd ce cf  │····│····│····│····│
        000000d0  d0 d1 d2 d3  d4 d5 d6 d7  d8 d9 da db  dc dd de df  │····│····│····│····│
        000000e0  e0 e1 e2 e3  e4 e5 e6 e7  e8 e9 ea eb  ec ed ee ef  │····│····│····│····│
        000000f0  f0 f1 f2 f3  f4 f5 f6 f7  f8 f9 fa fb  fc fd fe ff  │····│····│····│····│
        00000100

        >>> print(hexdump(bytearray(range(256)), hexii=True))
        00000000      01  02  03   04  05  06  07   08  09  0a  0b   0c  0d  0e  0f  │
        00000010  10  11  12  13   14  15  16  17   18  19  1a  1b   1c  1d  1e  1f  │
        00000020  20  .!  ."  .#   .$  .%  .&  .'   .(  .)  .*  .+   .,  .-  ..  ./  │
        00000030  .0  .1  .2  .3   .4  .5  .6  .7   .8  .9  .:  .;   .<  .=  .>  .?  │
        00000040  .@  .A  .B  .C   .D  .E  .F  .G   .H  .I  .J  .K   .L  .M  .N  .O  │
        00000050  .P  .Q  .R  .S   .T  .U  .V  .W   .X  .Y  .Z  .[   .\  .]  .^  ._  │
        00000060  .`  .a  .b  .c   .d  .e  .f  .g   .h  .i  .j  .k   .l  .m  .n  .o  │
        00000070  .p  .q  .r  .s   .t  .u  .v  .w   .x  .y  .z  .{   .|  .}  .~  7f  │
        00000080  80  81  82  83   84  85  86  87   88  89  8a  8b   8c  8d  8e  8f  │
        00000090  90  91  92  93   94  95  96  97   98  99  9a  9b   9c  9d  9e  9f  │
        000000a0  a0  a1  a2  a3   a4  a5  a6  a7   a8  a9  aa  ab   ac  ad  ae  af  │
        000000b0  b0  b1  b2  b3   b4  b5  b6  b7   b8  b9  ba  bb   bc  bd  be  bf  │
        000000c0  c0  c1  c2  c3   c4  c5  c6  c7   c8  c9  ca  cb   cc  cd  ce  cf  │
        000000d0  d0  d1  d2  d3   d4  d5  d6  d7   d8  d9  da  db   dc  dd  de  df  │
        000000e0  e0  e1  e2  e3   e4  e5  e6  e7   e8  e9  ea  eb   ec  ed  ee  ef  │
        000000f0  f0  f1  f2  f3   f4  f5  f6  f7   f8  f9  fa  fb   fc  fd  fe  ##  │
        00000100

        >>> print(hexdump(b'X' * 64))
        00000000  58 58 58 58  58 58 58 58  58 58 58 58  58 58 58 58  │XXXX│XXXX│XXXX│XXXX│
        *
        00000040

        >>> print(hexdump(b'X' * 64, skip=False))
        00000000  58 58 58 58  58 58 58 58  58 58 58 58  58 58 58 58  │XXXX│XXXX│XXXX│XXXX│
        00000010  58 58 58 58  58 58 58 58  58 58 58 58  58 58 58 58  │XXXX│XXXX│XXXX│XXXX│
        00000020  58 58 58 58  58 58 58 58  58 58 58 58  58 58 58 58  │XXXX│XXXX│XXXX│XXXX│
        00000030  58 58 58 58  58 58 58 58  58 58 58 58  58 58 58 58  │XXXX│XXXX│XXXX│XXXX│
        00000040

        >>> print(hexdump(fit({0x10: b'X'*0x20, 0x50-1: b'\xff'*20}, length=0xc0) + b'\x00'*32))
        00000000  61 61 61 61  62 61 61 61  63 61 61 61  64 61 61 61  │aaaa│baaa│caaa│daaa│
        00000010  58 58 58 58  58 58 58 58  58 58 58 58  58 58 58 58  │XXXX│XXXX│XXXX│XXXX│
        *
        00000030  6d 61 61 61  6e 61 61 61  6f 61 61 61  70 61 61 61  │maaa│naaa│oaaa│paaa│
        00000040  71 61 61 61  72 61 61 61  73 61 61 61  74 61 61 ff  │qaaa│raaa│saaa│taa·│
        00000050  ff ff ff ff  ff ff ff ff  ff ff ff ff  ff ff ff ff  │····│····│····│····│
        00000060  ff ff ff 61  7a 61 61 62  62 61 61 62  63 61 61 62  │···a│zaab│baab│caab│
        00000070  64 61 61 62  65 61 61 62  66 61 61 62  67 61 61 62  │daab│eaab│faab│gaab│
        00000080  68 61 61 62  69 61 61 62  6a 61 61 62  6b 61 61 62  │haab│iaab│jaab│kaab│
        00000090  6c 61 61 62  6d 61 61 62  6e 61 61 62  6f 61 61 62  │laab│maab│naab│oaab│
        000000a0  70 61 61 62  71 61 61 62  72 61 61 62  73 61 61 62  │paab│qaab│raab│saab│
        000000b0  74 61 61 62  75 61 61 62  76 61 61 62  77 61 61 62  │taab│uaab│vaab│waab│
        000000c0  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
        *
        000000e0

        >>> print(hexdump(fit({0x10: b'X'*0x20, 0x50-1: b'\xff'*20}, length=0xc0) + b'\x00'*32, cyclic=1))
        00000000  61 61 61 61  62 61 61 61  63 61 61 61  64 61 61 61  │aaaa│baaa│caaa│daaa│
        00000010  58 58 58 58  58 58 58 58  58 58 58 58  58 58 58 58  │XXXX│XXXX│XXXX│XXXX│
        *
        00000030  6d 61 61 61  6e 61 61 61  6f 61 61 61  70 61 61 61  │maaa│naaa│oaaa│paaa│
        00000040  71 61 61 61  72 61 61 61  73 61 61 61  74 61 61 ff  │qaaa│raaa│saaa│taa·│
        00000050  ff ff ff ff  ff ff ff ff  ff ff ff ff  ff ff ff ff  │····│····│····│····│
        00000060  ff ff ff 61  7a 61 61 62  62 61 61 62  63 61 61 62  │···a│zaab│baab│caab│
        00000070  64 61 61 62  65 61 61 62  66 61 61 62  67 61 61 62  │daab│eaab│faab│gaab│
        *
        000000c0  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
        *
        000000e0

        >>> print(hexdump(fit({0x10: b'X'*0x20, 0x50-1: b'\xff'*20}, length=0xc0) + b'\x00'*32, cyclic=1, hexii=1))
        00000000  .a  .a  .a  .a   .b  .a  .a  .a   .c  .a  .a  .a   .d  .a  .a  .a  │
        00000010  .X  .X  .X  .X   .X  .X  .X  .X   .X  .X  .X  .X   .X  .X  .X  .X  │
        *
        00000030  .m  .a  .a  .a   .n  .a  .a  .a   .o  .a  .a  .a   .p  .a  .a  .a  │
        00000040  .q  .a  .a  .a   .r  .a  .a  .a   .s  .a  .a  .a   .t  .a  .a  ##  │
        00000050  ##  ##  ##  ##   ##  ##  ##  ##   ##  ##  ##  ##   ##  ##  ##  ##  │
        00000060  ##  ##  ##  .a   .z  .a  .a  .b   .b  .a  .a  .b   .c  .a  .a  .b  │
        00000070  .d  .a  .a  .b   .e  .a  .a  .b   .f  .a  .a  .b   .g  .a  .a  .b  │
        *
        000000c0                                                                     │
        *
        000000e0

        >>> print(hexdump(b'A'*16, width=9))
        00000000  41 41 41 41  41 41 41 41  41  │AAAA│AAAA│A│
        00000009  41 41 41 41  41 41 41         │AAAA│AAA│
        00000010
        >>> print(hexdump(b'A'*16, width=10))
        00000000  41 41 41 41  41 41 41 41  41 41  │AAAA│AAAA│AA│
        0000000a  41 41 41 41  41 41               │AAAA│AA│
        00000010
        >>> print(hexdump(b'A'*16, width=11))
        00000000  41 41 41 41  41 41 41 41  41 41 41  │AAAA│AAAA│AAA│
        0000000b  41 41 41 41  41                     │AAAA│A│
        00000010
        >>> print(hexdump(b'A'*16, width=12))
        00000000  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│
        0000000c  41 41 41 41                            │AAAA│
        00000010
        >>> print(hexdump(b'A'*16, width=13))
        00000000  41 41 41 41  41 41 41 41  41 41 41 41  41  │AAAA│AAAA│AAAA│A│
        0000000d  41 41 41                                   │AAA│
        00000010
        >>> print(hexdump(b'A'*16, width=14))
        00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41  │AAAA│AAAA│AAAA│AA│
        0000000e  41 41                                         │AA│
        00000010
        >>> print(hexdump(b'A'*16, width=15))
        00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41  │AAAA│AAAA│AAAA│AAA│
        0000000f  41                                               │A│
        00000010

        >>> print(hexdump(b'A'*24, width=16, groupsize=8))
        00000000  41 41 41 41 41 41 41 41  41 41 41 41 41 41 41 41  │AAAAAAAA│AAAAAAAA│
        00000010  41 41 41 41 41 41 41 41                           │AAAAAAAA│
        00000018
        >>> print(hexdump(b'A'*24, width=16, groupsize=-1))
        00000000  41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41  │AAAAAAAAAAAAAAAA│
        00000010  41 41 41 41 41 41 41 41                          │AAAAAAAA│
        00000018

        >>> print(hexdump(b'A'*24, width=16, total=False))
        00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
        00000010  41 41 41 41  41 41 41 41                            │AAAA│AAAA│
        >>> print(hexdump(b'A'*24, width=16, groupsize=8, total=False))
        00000000  41 41 41 41 41 41 41 41  41 41 41 41 41 41 41 41  │AAAAAAAA│AAAAAAAA│
        00000010  41 41 41 41 41 41 41 41                           │AAAAAAAA│
    """
    s = packing.flat(s, stacklevel=1)
    return '\n'.join(hexdump_iter(BytesIO(s),
                                  width,
                                  skip,
                                  hexii,
                                  begin,
                                  style,
                                  highlight,
                                  cyclic,
                                  groupsize,
                                  total))

def negate(value, width = None):
    """
    Returns the two's complement of 'value'.
    """
    if width is None:
        width = context.bits
    mask = ((1<<width)-1)
    return ((mask+1) - value) & mask

def bnot(value, width=None):
    """
    Returns the binary inverse of 'value'.
    """
    if width is None:
        width = context.bits
    mask = ((1<<width)-1)
    return mask ^ value
