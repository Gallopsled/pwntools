# top-level imports
import struct, pwn, sys, subprocess, re, time, log, text, hashlib
from socket import htons, inet_aton, inet_ntoa, gethostbyname
from os import system
from time import sleep

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
    return struct.pack('<B', x & 0xff)

def p8b(x):
    return struct.pack('>B', x & 0xff)

def p16(x):
    return struct.pack('<H', x & 0xffff)

def p16b(x):
    return struct.pack('>H', x & 0xffff)

def p32(x):
    return struct.pack('<I', x & 0xffffffff)

def p32b(x):
    return struct.pack('>I', x & 0xffffffff)

def p64(x):
    return struct.pack('<Q', x & 0xffffffffffffffff)

def p64b(x):
    return struct.pack('>Q', x & 0xffffffffffffffff)

def u8(x):
    return struct.unpack('<B', x)[0]

def u8b(x):
    return struct.unpack('>B', x)[0]

def u16(x):
    return struct.unpack('<H', x)[0]

def u16b(x):
    return struct.unpack('>H', x)[0]

def u32(x):
    return struct.unpack('<I', x)[0]

def u32b(x):
    return struct.unpack('>I', x)[0]

def u64(x):
    return struct.unpack('<Q', x)[0]

def u64b(x):
    return struct.unpack('>Q', x)[0]

def flat(*args, **kwargs):
    func = kwargs.get('func', p32)

    obj = args[0] if len(args) == 1 else args

    if isinstance(obj, str):
        return obj
    elif isinstance(obj, int):
        return func(obj)
    else:
        return "".join(flat(o, func=func) for o in obj)

def dehex(s):
    return s.decode('hex')

def unhex(s):
    return s.decode('hex')

def enhex(s):
    return s.encode('hex')

def escape(s):
    return ''.join(['%%%02x' % ord(c) for c in s])

# align
def alignup(alignment, x):
    a = alignment
    return ((x + a - 1) / a) * a

def aligndown(alignment, x):
    a = alignment
    return (x / a) * a

def align(alignment, x):
    return alignup(alignment, x)

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
        return (lambda x: file(x).digest(),
                lambda x: sum(x).digest(),
                lambda x: file(x).hexdigest(),
                lambda x: sum(x).hexdigest())
    file, sum, filehex, sumhex = _closure()
    globals()[_algo + 'file'] = file
    globals()[_algo + 'sum'] = sum
    globals()[_algo + 'filehex'] = filehex
    globals()[_algo + 'sumhex'] = sumhex
# ugliest hack
del _algo, _closure

# network utils
def ip (host):
    return struct.unpack('I', inet_aton(gethostbyname(host)))[0]

def get_interfaces():
    d = subprocess.check_output('ip -4 -o addr', shell=True)
    ifs = re.findall(r'^\S+:\s+(\S+)\s+inet\s+([^\s/]+)', d, re.MULTILINE)
    return [i for i in ifs if i[0] != 'lo']

# Stuff
def pause(n = None):
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

def die(s = None, e = None, error_code = -1):
    if s:
        log.failure('FATAL: ' + s)
    if e:
        log.failure('The exception was:')
        log.trace(str(e) + '\n')
    exit(error_code)

def size(n, abbriv = 'B', si = False):
    '''Convert number to human readable form'''
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
    r = raw_input(' ' + text.bold('[?]') + ' ' + s)
    if r: return r
    return default
