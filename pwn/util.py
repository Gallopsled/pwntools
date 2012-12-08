import struct, sys, subprocess, re, pwn, pwn.text, functools, inspect

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
            pwn.info('Paused (press enter to continue)')
            raw_input('')
        else:
            pwn.waitfor('Continueing in')
            for i in range(n, 0, -1):
                pwn.status('%d... ' % i)
                pwn.sleep(1)
            pwn.succeeded('Now')
    except KeyboardInterrupt:
        pwn.warning('Interrupted')
        sys.exit(1)

def die(s = None, e = None, exit_code = -1):
    """Exits the program with an error string and optionally prints an exception."""
    if s:
        pwn.failure('FATAL: ' + s)
    if e:
        pwn.failure('The exception was:')
        pwn.trace(str(e) + '\n')
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
    r = raw_input(' ' + pwn.text.bold('[?]') + ' ' + s)
    if r: return r
    return default

# stuff mostly for decorators
def kwargs_remover(f, kwargs, check_list = None, clone = True):
    '''Removes all the keys from a kwargs-list, that a given function does not understand.
    
    The keys removed can optionally be restricted, so only keys from check_list are removed.'''

    if check_list == None: check_list = kwargs.keys()
    if clone: kwargs = kwargs.copy()
    if not f.func_code.co_flags & 8:
        for c in check_list:
            if c not in f.func_code.co_varnames:
                del kwargs[c]
    return kwargs

def method_signature(f):
    '''Returns the method signature for a function.'''
    spec = list(inspect.getargspec(f))
    if spec[3] == None: spec[3] = []

    args = []

    def simple_arg(a):
        if isinstance(a, list):
            return '(' + ', '.join(map(simple_arg, a)) + ')'
        return str(a)

    if spec[2] != None:
        args.append('**' + spec[2])
    if spec[1] != None:
        args.append('*' + spec[1])

    for n in range(len(spec[0])):
        cur = spec[0][len(spec[0])-n-1]
        
        if n < len(spec[3]):
            args.append(str(cur) + ' = ' + repr(spec[3][len(spec[3])-n-1]))
        else:
            args.append(simple_arg(cur))
    return f.func_name + '(' + ', '.join(reversed(args)) + ')'

def ewraps(wrapped):
    '''Extended version of functools.wraps.
    
    This version also adds the original method signature to the docstring.'''
    def deco(wrapper):
        semi_fixed = functools.wraps(wrapped)(wrapper)
        if not wrapped.__dict__.get('signature_added', False):
            semi_fixed.__doc__ = method_signature(wrapped) + '\n\n' + (semi_fixed.__doc__ or '')
        semi_fixed.__dict__['signature_added'] = True
        return semi_fixed
    return deco
