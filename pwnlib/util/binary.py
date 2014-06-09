def unhex(s):
    """Hex-decodes a string"""
    return s.decode('hex')

def enhex(x):
    """Hex-encodes a string or integer"""
    return x.encode('hex')

def urlencode(s):
    """urlencodes a string"""
    return ''.join(['%%%02x' % ord(c) for c in s])

def urldecode(s, ignore_invalid = False):
    """urldecodes a string"""
    import re
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
                raise Exception("Invalid input to urldecode")
    return res

def bits(s, endian = 'big', zero = None, one = None, type = None, size = None):
    '''Converts the argument into a string of binary sequence
       or a binary integer list

       Arguments:
         - s: The sequence which should be parsed.
         - endian(optional): The binary endian, default 'big'.
         - zero(optional): The byte representing a 0bit, required if
            one is defined.
         - one(optional): The byte representing a 1bit, required if
            zero is defined.
         - type(optional): A string representing the input type, can be
            'bool' or 'str', defaults to integer if not defined.
         - size: Number of bits to output, None for minimum number of bits.

       Returns a string of 1s and 0s if type = 'str', else a list
         of bits. '''
    types = {bool:     'bool',
             'bool':   'bool',
             str:      'str',
             'str':    'str',
             'string': 'str',
             int:      'int',
             'int':    'int',
             None:     None}

    try:
        type = types[type]
    except:
        pwn.die("Wat. Unknown type %s" % str(type))

    if zero != None or one != None:
        if zero == None or one == None:
            pwn.die("Wat. You cannot specify just a zero or a one in bits")

        if type != None:
            pwn.die("You cannot specify both a type and (zero, one)")
    else:
        if type == 'bool':
            zero = False
            one = True
        elif type == 'str':
            zero = "0"
            one = "1"
        else:
            zero = 0
            one = 1

    out = []
    if isinstance(s, str):
        for c in s:
            b = ord(c)
            byte = []
            for _ in range(8):
                byte.append(one if b & 1 else zero)
                b >>= 1
            if endian == 'little':
                out += byte
            elif endian == 'big':
                out += byte[::-1]
            else:
                pwn.die('Wat (endian style)')
    elif pwn.isint(s):
        while s:
            bit, s = one if s & 1 else zero, s >> 1
            if endian == 'little':
                out.append(bit)
            else:
                out.insert(0, bit)
    else:
        print `s`
        pwn.die("Wat (bits does not support this type)")

    if size is not None:
        if len(out) < size:
            tail = [zero] * (size - len(out))
            if endian == 'little':
                out += tail
            else:
                out = tail + out
        else:
            if endian == 'little':
                out = out[:size]
            else:
                out = out[-size:]

    if type == 'str':
        return ''.join(out)
    else:
        return out

def bits_str(s, endian = 'big', zero = '0', one = '1', size = None):
    return ''.join(bits(s, zero=zero, one=one, endian=endian, size=size))

def unbits(s, endian = 'big'):
    out = []

    state = {'cur': ''}
    count = 0

    def flush():
        cur = state['cur'].ljust(8, '0')
        state['cur'] = ''
        if endian == 'little':
            out.append(chr(int(cur[::-1], 2)))
        elif endian == 'big':
            out.append(chr(int(cur, 2)))
        else:
            pwn.die('Wat (endian style)')

    for c in s:
        if c not in ['0', '1', 0, 1, True, False]:
            pwn.die('Unbits called with a funky argument')

        state['cur'] += '1' if c in ['1', 1, True] else '0'
        count += 1

        if count == 8:
            count = 0
            flush()
    if count:
        flush()

    return ''.join(out)

def bitflip(v):
    return ''.join([unbits(bits(c, endian = 'little')) for c in v])

def bitflip_int(v, width):
    return int(bits_str(v).rjust(width, '0')[::-1], 2)

def b64e(s):
    '''Base64 encodes a string'''
    import base64
    return base64.b64encode(s)

def b64d(s):
    '''Base64 decodes a string'''
    import base64
    return base64.b64decode(s)

# misc binary functions
def xor(*args, **kwargs):
    """Flattens its arguments and then xors them together.
If the end of a string is reached, it wraps around in the string.

Converts the output to a string or a list or tuple of ints or chrs
depending on the first input.

Arguments:
  - func: The function to use with flat. Defaults to p8.
  - cut: How long a string should be returned.
         Can be either 'min'/'max'/'left'/'right' or a number.
  - flat: Ignore type of first argument and flatten output in all
          cases. Defaults to False."""

    if len(args) == 0:
        return []

    cut = kwargs.get('cut', 'max')
    func = kwargs.get('func', p8)
    doflat = kwargs.get('flat', False)

    def output(xs):
        if doflat:
            return ''.join(chr(x) for x in xs)
        for con in list, tuple:
            if isinstance(args[0], con):
                if all(pwn.isint(x) for x in args[0]):
                    return con(xs)
                else:
                    return con(chr(x) for x in xs)
        return ''.join(chr(x) for x in xs)

    strs = filter(len, [map(ord, flat(s, func=func)) for s in args])

    if strs == []:
        return output([])

    if pwn.isint(cut):
        l = cut
    elif cut == 'left':
        l = len(strs[0])
    elif cut == 'right':
        l = len(strs[-1])
    elif cut == 'min':
        l = min(map(len, strs))
    elif cut == 'max':
        l = max(map(len, strs))
    else:
        raise Exception("Not a valid cut argument")

    def get(n):
        return reduce(lambda x, y: x ^ y, [s[n % len(s)] for s in strs])

    return output(get(n) for n in range(l))

def xor_pair(data, avoid=''):
    """Args: data
    Finds two pieces of data that will xor together into the argument, while avoiding
    the bytes specified using the avoid argument."""
    only = pwn.get_only()

    data = ''.join(data)

    res1 = ''
    res2 = ''

    for c1 in data:
        for c2 in only:
            if xor(c1, c2) in only:
                res1 += c2
                res2 += xor(c1, c2)
                break
        else:
            return None

    return (res1, res2)


def randoms(count, avoid):
    """Args: count
    Returns a number of random bytes, while avoiding the bytes specified using the avoid module."""
    import random
    return ''.join(random.choice(pwn.get_only()) for n in range(count))


def random8():
    """Returns a random number which fits inside 1 byte, while avoiding the bytes specified using the avoid module."""
    return u8(randoms(1))


def random16():
    """Returns a random number which fits inside 2 byte, while avoiding the bytes specified using the avoid module."""
    return u16(randoms(2))


def random32():
    """Returns a random number which fits inside 4 byte, while avoiding the bytes specified using the avoid module."""
    return u32(randoms(4))

def random64():
    """Returns a random number which fits inside 8 byte, while avoiding the bytes specified using the avoid module."""
    return u64(randoms(8))

def ror(n, k, size = None):
    """Returns ((n >> k) | (n << (size - k))) truncated to the right number of bits.

    Size defaults to 32 for numbers and 8*len(n) for strings.

    Lists and tupples are rotated as you would expect."""

    if isinstance(n, str):
        repack = len(n)
        size = size or (8*len(n))
        n = uint(n)
    elif all(hasattr(n, x) for x in ['__add__', '__getslice__', '__len__']):
        return n[(-k) % len(n):] + n[:(-k) % len(n)]
    else:
        repack = False
        size = size or 32

    k = ((k % size) + size) % size
    n = (n >> k) | (n << (size - k))
    n &= (1 << size) - 1

    if repack:
        return pint(n).ljust(repack, '\x00')
    else:
        return n

def rol(n, k, size = None):
    """Returns ((n << k) | (n >> (size - k))) truncated to the right number of bits.

    Size defaults to 32 for numbers and 8*len(n) for strings.

    Lists and tupples are rotated as you would expect."""
    return ror(n, -k, size)

def chunks(l, n):
    """ Yield successive n-sized chunks from l. """
    for i in xrange(0, len(l), n):
        yield l[i:i+n]

def isprint(c):
    """Return true if a character is printable"""
    return len(c)+2 == len(repr(c))


def hexii(s, width=16, skip=True, hexii=True):
    return hexdump(s, width, skip, hexii)

def hexiichar(c):
    from string import punctuation, digits, letters
    HEXII = punctuation + digits + letters
    if c in HEXII:      return ".%c " % c
    elif c == '\0':     return "   "
    elif c == '\xff':   return "## "
    else:               return "%02x " % ord(c)

def hexdump(s, width=16, skip=True, hexii=False):
    lines       = []
    last_unique = ''
    byte_width  = len('00 ')
    column_sep  = '  '
    line_fmt    = '%%(offset)08x  %%(hexbytes)-%is |%%(printable)s|' % (len(column_sep)+(width*byte_width))

    if hexii:
        column_sep = ''
        line_fmt   = '%%(offset)08x  %%(hexbytes)-%is|' % (len(column_sep)+(width*byte_width))

    for line,chunk in enumerate(chunks(s,width)):
        # If this chunk is the same as the last unique chunk,
        # use a '*' instead.
        if skip and (last_unique == chunk):
            if lines[-1] != '*':
                lines.append('*')
            continue

        # Chunk is unique, save for next iteration
        last_unique = chunk

        # Cenerate contents for line
        offset    = line*width
        if not hexii:
            hexbytes  = ''.join('%02x ' % ord(b) for b in chunk)
            printable = ''.join(b if isprint(b) else '.' for b in chunk)
        else:
            hexbytes  = ''.join(hexiichar(b) for b in chunk)
            printable = ''

        # Insert column break in middle, for even-width lines
        middle = (width/2)*byte_width
        if len(hexbytes) > middle:
            hexbytes = hexbytes[:middle] + column_sep + hexbytes[middle:]

        lines.append(line_fmt % locals())

    lines.append("%08x" % len(s))
    return '\n'.join(lines)
