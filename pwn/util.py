import struct, sys, subprocess, re, pwn
from pwn import log, text

# allowed/avoided
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

# align
def align_up(alignment, x):
    """Rounds x up to nearest multiple of the alignment."""
    a = alignment
    return ((x + a - 1) // a) * a

def align_down(alignment, x):
    """Rounds x down to nearest multiple of the alignment."""
    a = alignment
    return (x // a) * a

def align(alignment, x):
    """Rounds x up to nearest multiple of the alignment."""
    return align_up(alignment, x)

# network utils
def ip (host):
    """Resolve host and return IP as four byte string"""
    return struct.unpack('I', pwn.inet_aton(pwn.gethostbyname(host)))[0]

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
                pwn.sleep(1)
            log.succeeded('Now')
    except KeyboardInterrupt:
        log.warning('Interrupted')
        sys.exit(1)

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
