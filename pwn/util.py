import struct, sys, subprocess, re, pwn, time

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

def read(path):
    with open(path) as f:
        return f.read()

def write(path, data):
    with open(path, 'w') as f:
        f.write(data)

def bash(cmd, timeout = None, return_stderr = False):
    p = subprocess.Popen(['/bin/bash', '-c', cmd],
                         stdin  = subprocess.PIPE,
                         stdout = subprocess.PIPE,
                         stderr = subprocess.PIPE)
    if timeout is None:
        o, e = p.communicate()
    else:
        t = time.time()
        while time.time() - t < timeout:
            time.sleep(0.01)
            if p.poll() is not None:
                break
        if p.returncode is None:
            p.kill()
        o, e = p.communicate()
    if return_stderr:
        return o, e
    return o
