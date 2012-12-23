import struct, re, base64, random, pwn

# conversion functions
def p8(x):
    """Packs an integer into a 1-byte string"""
    return struct.pack('<B', x & 0xff)

def p8b(x):
    """Packs an integer into a 1-byte string"""
    return struct.pack('>B', x & 0xff)

def p16(x):
    """Packs an integer into a 2-byte string (little endian)"""
    return struct.pack('<H', x & 0xffff)

def p16b(x):
    """Packs an integer into a 2-byte string (big endian)"""
    return struct.pack('>H', x & 0xffff)

def p32(x):
    """Packs an integer into a 4-byte string (little endian)"""
    return struct.pack('<I', x & 0xffffffff)

def p32b(x):
    """Packs an integer into a 4-byte string (big endian)"""
    return struct.pack('>I', x & 0xffffffff)

def p64(x):
    """Packs an integer into a 8-byte string (little endian)"""
    return struct.pack('<Q', x & 0xffffffffffffffff)

def p64b(x):
    """Packs an integer into a 8-byte string (big endian)"""
    return struct.pack('>Q', x & 0xffffffffffffffff)

def u8(x):
    """Unpacks a 1-byte string into an integer"""
    return struct.unpack('<B', x)[0]

def u8b(x):
    """Unpacks a 1-byte string into an integer"""
    return struct.unpack('>B', x)[0]

def u16(x):
    """Unpacks a 2-byte string into an integer (little endian)"""
    return struct.unpack('<H', x)[0]

def u16b(x):
    """Unpacks a 2-byte string into an integer (big endian)"""
    return struct.unpack('>H', x)[0]

def u32(x):
    """Unpacks a 4-byte string into an integer (little endian)"""
    return struct.unpack('<I', x)[0]

def u32b(x):
    """Unpacks a 4-byte string into an integer (big endian)"""
    return struct.unpack('>I', x)[0]

def u64(x):
    """Unpacks a 8-byte string into an integer (little endian)"""
    return struct.unpack('<Q', x)[0]

def u64b(x):
    """Unpacks a 8-byte string into an integer (big endian)"""
    return struct.unpack('>Q', x)[0]

def flat(*args, **kwargs):
    """Flattens the arguments into a string.
Takes a single named argument 'func', which defaults to p32.
  - Strings are returned
  - Integers are converted using the 'func' argument.
  - Shellcode is assembled
  - Enumerables (such as lists) traversed recursivly and the concatenated.

Example:
  - flat(5, "hello", [[6, "bar"], "baz"]) == '\\x05\\x00\\x00\\x00hello\\x06\\x00\\x00\\x00barbaz'
"""
    from pwn.internal.shellcode_helper import AssemblerBlock

    func = kwargs.get('func', p32)

    obj = args[0] if len(args) == 1 else args

    if isinstance(obj, str):
        return obj
    elif isinstance(obj, int):
        return func(obj)
    elif isinstance(obj, AssemblerBlock):
        return pwn.asm(obj)
    else:
        return "".join(flat(o, func=func) for o in obj)

def dehex(s):
    """Hex-decodes a string"""
    return s.decode('hex')

def unhex(s):
    """Hex-decodes a string"""
    return s.decode('hex')

def enhex(s):
    """Hex-encodes a string"""
    return s.encode('hex')

def urlencode(s):
    """urlencodes a string"""
    return ''.join(['%%%02x' % ord(c) for c in s])

def urldecode(s, ignore_invalid = False):
    """urldecodes a string"""
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



def bits(s, **kwargs):
    types = {bool:     'bool',
             'bool':   'bool',
             str:      'str',
             'str':    'str',
             'string': 'str',
             int:      'int',
             'int':    'int',
             None:     None}

    endian = kwargs.get('endian', 'big')
    zero   = kwargs.get('zero', None)
    one    = kwargs.get('one', None)
    type   = kwargs.get('type', None)

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

def bits_str(s, **kwargs):
    endian = kwargs.get('endian', 'big')
    zero   = kwargs.get('zero', "0")
    one    = kwargs.get('one', "1")

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
    return base64.b64encode(s)

def b64e(s):
    return b64(s)

def b64d(s):
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

def xor_pair(data, **kwargs):
    """Args: data [avoid = '\\x00'] [only = every character]
    Finds two pieces of data that will xor together into the argument, while avoiding
    the bytes specified."""
    allowed = pwn.get_allowed(**kwargs)

    data = flat(data)

    res1 = ''
    res2 = ''

    for c1 in data:
        for c2 in allowed:
            if xor(c1, c2) in allowed:
                res1 += c2
                res2 += xor(c1, c2)
                break

    return (res1, res2)

def randoms(count, **kwargs):
    """Args: count [avoid = '\x00'] [only = every character]
    Returns a number of random bytes, which avoid the specified bytes."""
    allowed = pwn.get_allowed(**kwargs)
    return ''.join(random.choice(allowed) for n in range(count))

def random8(**kwargs):
    """Args: [avoid = '\x00'] [only = every character]
    Returns a random number which fits inside a byte."""
    return u8(randoms(1, **kwargs))

def random16(**kwargs):
    """Args: [avoid = '\x00'] [only = every character]
    Returns a random number which fits inside a 2 bytes."""
    return u16(randoms(2, **kwargs))

def random32(**kwargs):
    """Args: [avoid = '\x00'] [only = every character]
    Returns a random number which fits inside a 4 bytes."""
    return u32(randoms(4, **kwargs))

def random64(**kwargs):
    """Args: [avoid = '\x00'] [only = every character]
    Returns a random number which fits inside a 8 bytes."""
    return u64(randoms(8, **kwargs))
