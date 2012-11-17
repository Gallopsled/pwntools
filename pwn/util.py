# top-level imports
import struct, pwn, sys, subprocess, re, time, log, text, hashlib
from socket import htons, inet_aton, inet_ntoa, gethostbyname
from os import system
from time import sleep
import random

# list utils
def group(lst, n):
    """group([0,3,4,10,2,3], 2) => [(0,3), (4,10), (2,3)]

    Group a list into consecutive n-tuples. Incomplete tuples are
    discarded e.g.

    >>> group(range(10), 3)
    [(0, 1, 2), (3, 4, 5), (6, 7, 8)]
    """
    return zip(*[lst[i::n] for i in range(n)])

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
  - Enumerables (such as lists) traversed recursivly and the concatenated.

Example:
  - flat(5, "hello", [[6, "bar"], "baz"]) == '\\x05\\x00\\x00\\x00hello\\x06\\x00\\x00\\x00barbaz'
"""
    func = kwargs.get('func', p32)

    obj = args[0] if len(args) == 1 else args

    if isinstance(obj, str):
        return obj
    elif isinstance(obj, int):
        return func(obj)
    else:
        return "".join(flat(o, func=func) for o in obj)

def flat8(*args):
    """Call flat with p8 as the func"""
    return flat(args, func=p8)

def flat8b(*args):
    """Call flat with p8b as the func"""
    return flat(args, func=p8)

def flat16(*args):
    """Call flat with p16 as the func"""
    return flat(args, func=p16)

def flat16b(*args):
    """Call flat with p16b as the func"""
    return flat(args, func=p16)

def flat32(*args):
    """Call flat with p32 as the func"""
    return flat(args, func=p32)

def flat32b(*args):
    """Call flat with p32b as the func"""
    return flat(args, func=p32)

def flat64(*args):
    """Call flat with p64 as the func"""
    return flat(args, func=p64)

def flat64b(*args):
    """Call flat with p64b as the func"""
    return flat(args, func=p64)

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

def get_allowed(**kwargs):
    """Args: [avoid = '\\x00'] [only = every character]
    For a set of avoided and exclusively-used characters, return the bytes allowed considering both."""
    avoid     = kwargs.get('avoid', '\x00')
    only      = kwargs.get('only', map(chr, range(256)))

    return [chr(b) for b in range(256) if chr(b) not in avoid and chr(b) in only]

def get_avoided(**kwargs):
    """Args: [avoid = '\\x00'] [only = every character]
    For a set of avoided and exclusively-used characters, return the bytes avoided considering both."""
    avoid     = kwargs.get('avoid', '\x00')
    only      = kwargs.get('only', map(chr, range(256)))

    return [chr(b) for b in range(256) if chr(b) in avoid or chr(b) not in only]

def xor_pair(data, **kwargs):
    """Args: data [avoid = '\\x00'] [only = every character]
    Finds two pieces of data that will xor together into the argument, while avoiding
    the bytes specified."""
    allowed = get_allowed(**kwargs)

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
    allowed = get_allowed(**kwargs)
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

# align
def align_up(alignment, x):
    """Rounds x up to nearest multiple of the alignment."""
    a = alignment
    return ((x + a - 1) / a) * a

def align_down(alignment, x):
    """Rounds x down to nearest multiple of the alignment."""
    a = alignment
    return (x / a) * a

def align(alignment, x):
    """Rounds x up to nearest multiple of the alignment."""
    return align_up(alignment, x)

# hash
for _algo in hashlib.algorithms:
    def _closure():
        hash = hashlib.__dict__[_algo]
        def file(p):
            h = hash()
            fd = open(p)
            while True:
                s = fd.read(4096)
                if not s: break
                h.update(s)
            fd.close()
            return h
        def sum(s):
            return hash(s)
        file = lambda x: file(x).digest()
        file.__doc__ = 'Calculates the %s sum of a file' % _algo
        sum = lambda x: sum(x).digest()
        sum.__doc__ = 'Calculates the %s sum of a string' % _algo
        fileh = lambda x: file(x).hexdigest()
        fileh.__doc__ = 'Calculates the %s sum of a file; returns hex-encoded' % _algo
        sumh = lambda x: sum(x).hexdigest()
        sumh.__doc__ = 'Calculates the %s sum of a string; returns hex-encoded' % _algo
        return file, sum, fileh, sumh
    file, sum, filehex, sumhex = _closure()
    globals()[_algo + 'file'] = file
    globals()[_algo + 'sum'] = sum
    globals()[_algo + 'filehex'] = filehex
    globals()[_algo + 'sumhex'] = sumhex
# ugliest hack
del _algo, _closure

# network utils
def ip (host):
    """Resolve host and return IP as four byte string"""
    return struct.unpack('I', inet_aton(gethostbyname(host)))[0]

def get_interfaces():
    """Gets all (interface, IPv4) of the local system."""
    d = subprocess.check_output('ip -4 -o addr', shell=True)
    ifs = re.findall(r'^\S+:\s+(\S+)\s+inet\s+([^\s/]+)', d, re.MULTILINE)
    return [i for i in ifs if i[0] != 'lo']

# Stuff
def pause(n = None):
    """Waits for either user input or a specific number of seconds."""
    try:
        if n is None:
            log.info('Paused (press enter to continue)')
            raw_input('')
        else:
            log.waitfor('Continueing in')
            for i in range(n, 0, -1):
                log.status('%d... ' % i)
                time.sleep(1)
            log.succeeded('Now')
    except KeyboardInterrupt:
        log.warning('Interrupted')
        exit(1)

def die(s = None, e = None, exit_code = -1):
    """Exits the program with an error string and optionally prints an exception."""
    if s:
        log.failure('FATAL: ' + s)
    if e:
        log.failure('The exception was:')
        log.trace(str(e) + '\n')
    sys.exit(exit_code)

def size(n, abbriv = 'B', si = False):
    """Convert number to human readable form"""
    base = 1000.0 if si else 1024.0
    if n < base:
        return '%d%s' % (n, abbriv)

    for suffix in ['K', 'M', 'G', 'T']:
        n /= base
        if n <= base:
            num = '%.2f' % n
            while num[-1] == '0':
                num = num[:-1]
            if num[-1] == '.':
                num = num[:-1]
            return '%s%s%s' % (num, suffix, abbriv)

    return '%.2fP%s' % (n, abbriv)

def prompt(s, default = ''):
    """Prompts the user for input"""
    r = raw_input(' ' + text.bold('[?]') + ' ' + s)
    if r: return r
    return default
