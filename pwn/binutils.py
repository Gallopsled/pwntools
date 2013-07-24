import pwn
_AssemblerBlock = None

# conversion functions
def pint(x):
    '''Packs an integer into a string as long as needed, little endian'''
    out = ''
    while True:
        b = x & 0xff
        out += p8(b)
        x = x >> 8
        if x == 0 or x == -1:
            break
    return out

def pintb(x):
    '''Packs an integer into a string as long as needed, endian'''
    out = []
    while True:
        b = x & 0xff
        out.insert(0, p8(b))
        x = x >> 8
        if x == 0 or x == -1:
            break
    return ''.join(out)

def uint(x):
    '''Unpacks a string of arbitrary length into an integer, little endian'''
    out = 0
    for b in x[::-1]:
        out <<= 8
        out += u8(b)
    return out

def uintb(x):
    '''Unpacks a string of arbitrary length into an integer, big endian'''
    out = 0
    for b in x:
        out <<= 8
        out += u8(b)
    return out

def p8(x):
    """Packs an integer into a 1-byte string"""
    import struct
    return struct.pack('<B', x & 0xff)

def p8b(x):
    """Packs an integer into a 1-byte string"""
    import struct
    return struct.pack('>B', x & 0xff)

def p16(x):
    """Packs an integer into a 2-byte string (little endian)"""
    import struct
    return struct.pack('<H', x & 0xffff)

def p16b(x):
    """Packs an integer into a 2-byte string (big endian)"""
    import struct
    return struct.pack('>H', x & 0xffff)

def p32(x):
    """Packs an integer into a 4-byte string (little endian)"""
    import struct
    return struct.pack('<I', x & 0xffffffff)

def p32b(x):
    """Packs an integer into a 4-byte string (big endian)"""
    import struct
    return struct.pack('>I', x & 0xffffffff)

def p64(x):
    """Packs an integer into a 8-byte string (little endian)"""
    import struct
    return struct.pack('<Q', x & 0xffffffffffffffff)

def p64b(x):
    """Packs an integer into a 8-byte string (big endian)"""
    import struct
    return struct.pack('>Q', x & 0xffffffffffffffff)

def u8(x):
    """Unpacks a 1-byte string into an integer"""
    import struct
    return struct.unpack('<B', x)[0]

def u8b(x):
    """Unpacks a 1-byte string into an integer"""
    import struct
    return struct.unpack('>B', x)[0]

def u16(x):
    """Unpacks a 2-byte string into an integer (little endian)"""
    import struct
    return struct.unpack('<H', x)[0]

def u16b(x):
    """Unpacks a 2-byte string into an integer (big endian)"""
    import struct
    return struct.unpack('>H', x)[0]

def u32(x):
    """Unpacks a 4-byte string into an integer (little endian)"""
    import struct
    return struct.unpack('<I', x)[0]

def u32b(x):
    """Unpacks a 4-byte string into an integer (big endian)"""
    import struct
    return struct.unpack('>I', x)[0]

def u64(x):
    """Unpacks a 8-byte string into an integer (little endian)"""
    import struct
    return struct.unpack('<Q', x)[0]

def u64b(x):
    """Unpacks a 8-byte string into an integer (big endian)"""
    import struct
    return struct.unpack('>Q', x)[0]

@pwn.need_context
def p(x, arch = None):
    """Packs an integer into a string based on the current context"""
    if arch == 'amd64':
        return p64(x)
    elif arch == 'i386':
        return p32(x)
    pwn.die('Architecture not set in the context while calling p(%d)' % x)

@pwn.need_context
def u(x, arch = None):
    """Unpacks a string into an integer based on the current context"""
    if arch == 'amd64':
        return u64(x)
    elif arch == 'i386':
        return u32(x)
    pwn.die('Architecture not set in the context while calling u(%s)' % repr(x))

def pack_size(f):
    if f == p8:   return "8"
    if f == p16:  return "16"
    if f == p32:  return "32"
    if f == p64:  return "64"

    if f == p8b:  return "8b"
    if f == p16b: return "16b"
    if f == p32b: return "32b"
    if f == p64b: return "64b"

    return ""

packs_big_endian      = {64: p64b, 32: p32b, 16: p16b, 8: p8b, 'any': pintb}
packs_little_endian   = {64: p64,  32: p32,  16: p16,  8: p8,  'any': pint}
unpacks_big_endian    = {64: u64b, 32: u32b, 16: u16b, 8: u8b, 'any': uintb}
unpacks_little_endian = {64: u64,  32: u32,  16: u16,  8: u8,  'any': uint}

@pwn.need_context
def flat(*args, **kwargs):
    """Flattens the arguments into a string.
Takes a single named argument 'func', which defaults to "p32" if no context is set and to "p" otherwise.
  - Strings are returned
  - Integers are converted using the 'func' argument.
  - Shellcode is assembled
  - Enumerables (such as lists) traversed recursivly and the concatenated.

Example:
  - flat(5, "hello", [[6, "bar"], "baz"]) == '\\x05\\x00\\x00\\x00hello\\x06\\x00\\x00\\x00barbaz'
"""

    global _AssemblerBlock

    if _AssemblerBlock == None:
        from pwn.internal.shellcode_helper import AssemblerBlock as _AssemblerBlock

    if 'arch' in kwargs and kwargs['arch'] != None:
        default_func = p
    else:
        default_func = p32

    func = kwargs.get('func', default_func)

    obj = args[0] if len(args) == 1 else args

    if isinstance(obj, str):
        return obj
    elif isinstance(obj, int):
        return func(obj)
    elif hasattr(obj, '__flat__'):
        return obj.__flat__()
    else:
        return "".join(flat(o, func=func) for o in obj)

def unhex(s):
    """Hex-decodes a string"""
    return s.decode('hex')

def enhex(x):
    """Hex-encodes a string or integer"""
    if isinstance(x, int):
        x = pint(x)
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

def bits(s, endian = 'big', zero = None, one = None, type = None):
    '''Converts the argument into a string of binary sequence 
       or a binary integer list

       Arguments:
         - s: The sequence which should be parsed.
         - endian(optional): The binary endian, default 'big'.
         - zero(optional): The byte representing a 0bit, required if
            one is defined.
         - one(optional): The byte representing a 1bit, required if
            zero is defined.
         - Type(optional): A string representing the input type, can be
            'bool' or 'str', defaults to integer if not defined.

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

    if type == 'str':
        return ''.join(out)
    else:
        return out

def bits_str(s, endian = 'big', zero = '0', one = '1'):
    return ''.join(bits(s, zero=zero, one=one, endian=endian))

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

def b64(s):
    '''Base64 encodes a string'''
    import base64
    return base64.b64encode(s)

def b64e(s):
    '''Base64 encncodes a string'''
    return b64(s)

def b64d(s):
    '''Base64 decodes a string'''
    import base64
    return base64.b64decode(s)

# misc binary functions
def xor(*args, **kwargs):
    """Flattens its arguments and then xors them together.
If the end of a string is reached, it wraps around in the string.

Arguments:
  - func: The function to use with flat. Defaults to p8.
  - cut: How long a string should be returned.
         Can be either 'min'/'max'/'left'/'right' or a number."""

    cut = kwargs.get('cut', 'max')
    func = kwargs.get('func', p8)

    strs = [map(ord, flat(s, func=func)) for s in args]

    if isinstance(cut, int):
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
        return chr(reduce(lambda x, y: x ^ y, [s[n % len(s)] for s in strs]))

    return ''.join(get(n) for n in range(l))

@pwn.avoider
def xor_pair(data):
    """Args: data
    Finds two pieces of data that will xor together into the argument, while avoiding
    the bytes specified using the avoid module."""
    only = pwn.get_only()

    data = flat(data)

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

@pwn.avoider
def randoms(count):
    """Args: count
    Returns a number of random bytes, while avoiding the bytes specified using the avoid module."""
    import random
    return ''.join(random.choice(pwn.get_only()) for n in range(count))

@pwn.avoider
def random8():
    """Returns a random number which fits inside 1 byte, while avoiding the bytes specified using the avoid module."""
    return u8(randoms(1))

@pwn.avoider
def random16():
    """Returns a random number which fits inside 2 byte, while avoiding the bytes specified using the avoid module."""
    return u16(randoms(2))

@pwn.avoider
def random32():
    """Returns a random number which fits inside 4 byte, while avoiding the bytes specified using the avoid module."""
    return u32(randoms(4))

@pwn.avoider
def random64():
    """Returns a random number which fits inside 8 byte, while avoiding the bytes specified using the avoid module."""
    return u64(randoms(8))

def ror(n, k, size = None):
    """Returns ((n >> k) | (n << (size - k))) truncated to the right number of bits.

    Size defaults to 32 for numbers and 8*len(n) for strings."""

    if isinstance(n, str):
        repack = len(n)
        size = size or (8*len(n))
        n = uint(n)
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

    Size defaults to 32 for numbers and 8*len(n) for strings."""
    return ror(n, -k, size)
