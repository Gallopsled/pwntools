# -*- coding: utf-8 -*-
import base64
import random
import re
import string
import StringIO

from . import lists
from . import packing
from ..context import context
from ..log import getLogger
from ..term import text
from .cyclic import cyclic
from .cyclic import cyclic_find

log = getLogger(__name__)

def unhex(s):
    r"""unhex(s) -> str

    Hex-decodes a string.

    Example:

        >>> unhex("74657374")
        'test'
        >>> unhex("F\n")
        '\x0f'
    """
    s = s.strip()
    if len(s) % 2 != 0:
        s = '0' + s
    return s.decode('hex')

def enhex(x):
    """enhex(x) -> str

    Hex-encodes a string.

    Example:

        >>> enhex("test")
        '74657374'
    """
    return x.encode('hex')

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

    Converts the argument a list of bits.

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
        >>> sum(bits("test"))
        17
        >>> bits(0)
        [0, 0, 0, 0, 0, 0, 0, 0]
    """
    if s < 0:
        s = s & ((1<<context.bits)-1)

    if endian not in ['little', 'big']:
        raise ValueError("bits(): 'endian' must be either 'little' or 'big'")
    else:
        little = endian == 'little'

    out = []
    if isinstance(s, str):
        for c in s:
            b = ord(c)
            byte = []
            for _ in range(8):
                byte.append(one if b & 1 else zero)
                b >>= 1
            if little:
                out += byte
            else:
                out += byte[::-1]
    elif isinstance(s, (int, long)):
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
       >>> bits_str("bits_str", endian = "little")
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
       '\\x80'
       >>> unbits([1], endian = 'little')
       '\\x01'
       >>> unbits(bits('hello'), endian = 'little')
       '\\x16\\xa666\\xf6'
    """
    if endian == 'little':
        u = lambda s: chr(int(s[::-1], 2))
    elif endian == 'big':
        u = lambda s: chr(int(s, 2))
    else:
        raise ValueError("unbits(): 'endian' must be either 'little' or 'big'")

    out = ''
    cur = ''

    for c in s:
        if c in ['1', 1, True]:
            cur += '1'
        elif c in ['0', 0, False]:
            cur += '0'
        else:
            raise ValueError("unbits(): cannot decode the value %r into a bit" % c)

        if len(cur) == 8:
            out += u(cur)
            cur = ''
    if cur:
        out += u(cur.ljust(8, '0'))

    return ''.join(out)


def bitswap(s):
    """bitswap(s) -> str

    Reverses the bits in every byte of a given string.

    Example:
        >>> bitswap("1234")
        '\\x8cL\\xcc,'
    """

    out = []

    for c in s:
        out.append(unbits(bits_str(c)[::-1]))

    return ''.join(out)

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

       >>> b64e("test")
       'dGVzdA=='
       """
    return base64.b64encode(s)

def b64d(s):
    """b64d(s) -> str

    Base64 decodes a string

    Example:

       >>> b64d('dGVzdA==')
       'test'
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
       >>> xor('lol', 'hello', 42)
       '. ***'
    """

    cut = kwargs.pop('cut', 'max')

    if kwargs != {}:
        raise TypeError("xor() got an unexpected keyword argument '%s'" % kwargs.pop()[0])

    if len(args) == 0:
        raise ValueError("Must have something to xor")

    strs = [packing.flat(s, word_size = 8, sign = False, endianness = 'little') for s in args]
    strs = [[ord(c) for c in s] for s in strs if s != '']

    if strs == []:
        return ''

    if isinstance(cut, (int, long)):
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
        return chr(reduce(lambda x, y: x ^ y, [s[n % len(s)] for s in strs]))

    return ''.join(get(n) for n in range(cut))

def xor_pair(data, avoid = '\x00\n'):
    """xor_pair(data, avoid = '\\x00\\n') -> None or (str, str)

    Finds two strings that will xor into a given string, while only
    using a given alphabet.

    Arguments:
        data (str): The desired string.
        avoid: The list of disallowed characters. Defaults to nulls and newlines.

    Returns:
        Two strings which will xor to the given string. If no such two strings exist, then None is returned.

    Example:

        >>> xor_pair("test")
        ('\\x01\\x01\\x01\\x01', 'udru')
    """

    if isinstance(data, (int, long)):
        data = packing.pack(data)

    alphabet = list(chr(n) for n in range(256) if chr(n) not in avoid)

    res1 = ''
    res2 = ''

    for c1 in data:
        if context.randomize:
            random.shuffle(alphabet)
        for c2 in alphabet:
            c3 = chr(ord(c1) ^ ord(c2))
            if c3 in alphabet:
                res1 += c2
                res2 += c3
                break
        else:
            return None

    return res1, res2

def xor_key(data, avoid='\x00\n', size=None):
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

        >>> xor_key("Hello, world")
        ('\x01\x01\x01\x01', 'Idmmn-!vnsme')
    """
    size = size or context.bytes

    if len(data) % size:
        log.error("Data must be padded to size for xor_key")

    words    = lists.group(size, data)
    columns  = [''] * size
    for word in words:
        for i,byte in enumerate(word):
            columns[i] += byte

    alphabet = list(chr(n) for n in range(256) if chr(n) not in avoid)

    result = ''

    for column in columns:
        if context.randomize:
            random.shuffle(alphabet)
        for c2 in alphabet:
            if all(chr(ord(c)^ord(c2)) in alphabet for c in column):
                result += c2
                break
        else:
            return None

    return result, xor(data, result)

def randoms(count, alphabet = string.lowercase):
    """randoms(count, alphabet = string.lowercase) -> str

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

    return ''.join(random.choice(alphabet) for _ in xrange(count))


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

    if not isinstance(word_size, (int, long)) or word_size <= 0:
        raise ValueError("rol(): 'word_size' must be a strictly positive integer")

    if not isinstance(k, (int, long)):
        raise ValueError("rol(): 'k' must be an integer")

    if isinstance(n, (str, unicode, list, tuple)):
        return n[k % len(n):] + n[:k % len(n)]
    elif isinstance(n, (int, long)):
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
    return c in string.ascii_letters + string.digits + string.punctuation + ' '


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
    HEXII = string.punctuation + string.digits + string.letters
    if c in HEXII:
        return ".%c " % c
    elif c == '\0':
        return "   "
    elif c == '\xff':
        return "## "
    else:
        return "%02x " % ord(c)

default_style = {
    'marker':       text.gray if text.has_gray else text.blue,
    'nonprintable': text.gray if text.has_gray else text.blue,
    '00':           text.red,
    '0a':           text.red,
    'ff':           text.green,
}

cyclic_pregen = ''

def sequential_lines(a,b):
    return (a+b) in cyclic_pregen

def update_cyclic_pregenerated(size):
    global cyclic_pregen
    cyclic_pregen = cyclic(size)

def hexdump_iter(fd, width=16, skip=True, hexii=False, begin=0, style=None,
                 highlight=None, cyclic=False):
    """hexdump_iter(s, width = 16, skip = True, hexii = False, begin = 0,
                    style = None, highlight = None, cyclic = False) -> str generator

    Return a hexdump-dump of a string as a generator of lines.  Unless you have
    massive amounts of data you probably want to use :meth:`hexdump`.

    Arguments:
        fd(file): File object to dump.  Use :meth:`StringIO.StringIO` or :meth:`hexdump` to dump a string.
        width(int): The number of characters per line
        skip(bool): Set to True, if repeated lines should be replaced by a "*"
        hexii(bool): Set to True, if a hexii-dump should be returned instead of a hexdump.
        begin(int):  Offset of the first byte to print in the left column
        style(dict): Color scheme to use.
        highlight(iterable): Byte values to highlight.
        cyclic(bool): Attempt to skip consecutive, unmodified cyclic lines

    Returns:
        A generator producing the hexdump-dump one line at a time.
    """
    style     = style or {}
    highlight = highlight or []

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
    column_sep  = '  '
    line_fmt    = '%%(offset)08x  %%(hexbytes)-%is │%%(printable)s│' % (len(column_sep)+(width*byte_width))
    spacer      = ' '
    marker      = (style.get('marker') or (lambda s:s))('│')

    if hexii:
        column_sep = ''
        line_fmt   = '%%(offset)08x  %%(hexbytes)-%is│' % (len(column_sep)+(width*byte_width))
    else:
        def style_byte(b):
            hbyte = '%02x' % ord(b)
            abyte = b if isprint(b) else '·'
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
        cache = [style_byte(chr(b)) for b in range(256)]

    if cyclic:
        update_cyclic_pregenerated(len(s))

    numb = 0
    while True:
        offset = begin + numb
        chunk = fd.read(width)
        if chunk == '':
            break
        numb += len(chunk)
        # If this chunk is the same as the last unique chunk,
        # use a '*' instead.
        if skip and \
           (last_unique == chunk or \
            (cyclic and sequential_lines(last_unique, chunk))):
            last_unique = chunk
            if not skipping:
                yield '*'
                skipping = True
            continue

        # Chunk is unique, save for next iteration
        last_unique = chunk
        skipping = False

        # Generate contents for line
        hexbytes = ''
        printable = ''
        for i, b in enumerate(chunk):
            if not hexii:
                hbyte, abyte = cache[ord(b)]
            else:
                hbyte, abyte = _hexiichar(b), ''

            if i % 4 == 3 and i < width - 1:
                hbyte += spacer
                abyte += marker

            hexbytes += hbyte + ' '
            printable += abyte

        if i + 1 < width:
            delta = width - i - 1
            hexbytes += ' ' * (byte_width * delta + (delta - 1) // 4)

        line = line_fmt % {'offset': offset, 'hexbytes': hexbytes, 'printable': printable}
        yield line

    line = "%08x" % (begin + numb)
    yield line

def hexdump(s, width=16, skip=True, hexii=False, begin=0,
            style=None, highlight=None, cyclic=False):
    """hexdump(s, width = 16, skip = True, hexii = False, begin = 0,
               style = None, highlight = None, cyclic = False) -> str generator

    Return a hexdump-dump of a string.

    Arguments:
        s(str): The data to hexdump.
        width(int): The number of characters per line
        skip(bool): Set to True, if repeated lines should be replaced by a "*"
        hexii(bool): Set to True, if a hexii-dump should be returned instead of a hexdump.
        begin(int):  Offset of the first byte to print in the left column
        style(dict): Color scheme to use.
        highlight(iterable): Byte values to highlight.
        cyclic(bool): Attempt to skip consecutive, unmodified cyclic lines

    Returns:
        A hexdump-dump in the form of a string.
"""
    s = packing.flat(s)
    return '\n'.join(hexdump_iter(StringIO.StringIO(s),
                                  width,
                                  skip,
                                  hexii,
                                  begin,
                                  style,
                                  highlight,
                                  cyclic))

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
