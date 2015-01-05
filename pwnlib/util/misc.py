import socket, re, os, stat, errno, string, base64, logging
from . import lists
log = logging.getLogger(__name__)

def align(alignment, x):
    """align(alignment, x) -> int

    Rounds `x` up to nearest multiple of the `alignment`.

    Example:
      >>> [align(5, n) for n in range(15)]
      [0, 5, 5, 5, 5, 5, 10, 10, 10, 10, 10, 15, 15, 15, 15]
    """
    return ((x + alignment - 1) // alignment) * alignment


def align_down(alignment, x):
    """align_down(alignment, x) -> int

    Rounds `x` down to nearest multiple of the `alignment`.

    Example:
        >>> [align_down(5, n) for n in range(15)]
        [0, 0, 0, 0, 0, 5, 5, 5, 5, 5, 10, 10, 10, 10, 10]
    """
    a = alignment
    return (x // a) * a


def binary_ip(host):
    """binary_ip(host) -> str

    Resolve host and return IP as four byte string.

    Example:
        >>> binary_ip("127.0.0.1")
        '\\x7f\\x00\\x00\\x01'
    """
    return socket.inet_aton(socket.gethostbyname(host))


def size(n, abbriv = 'B', si = False):
    """size(n, abbriv = 'B', si = False) -> str

    Convert the length of a bytestream to human readable form.

    Args:
      n(int,str): The length to convert to human readable form
      abbriv(str):

    Example:
        >>> size(451)
        '451B'
        >>> size(1000)
        '1000B'
        >>> size(1024)
        '1.00KB'
        >>> size(1024, si = True)
        '1.02KB'
        >>> [size(1024 ** n) for n in range(7)]
        ['1B', '1.00KB', '1.00MB', '1.00GB', '1.00TB', '1.00PB', '1024.00PB']
    """
    if isinstance(n, str):
        n = len(n)

    base = 1000.0 if si else 1024.0
    if n < base:
        return '%d%s' % (n, abbriv)

    for suffix in ['K', 'M', 'G', 'T']:
        n /= base
        if n < base:
            return '%.02f%s%s' % (n, suffix, abbriv)

    return '%.02fP%s' % (n / base, abbriv)


def read(path):
    """read(path) -> str

    Open file, return content.

    Examples:
        >>> read('pwnlib/util/misc.py').split('\\n')[0]
        'import socket, re, os, stat, errno, string, base64, logging'
    """
    path = os.path.expanduser(os.path.expandvars(path))
    with open(path) as fd:
        return fd.read()


def write(path, data = '', create_dir = False):
    """Create new file or truncate existing to zero length and write data."""
    path = os.path.expanduser(os.path.expandvars(path))
    if create_dir:
        path = os.path.realpath(path)
        mkdir_p(os.path.dirname(path))
    with open(path, 'w') as f:
        f.write(data)

def which(name, all = False):
    """which(name, flags = os.X_OK, all = False) -> str or str set

    Works as the system command ``which``; searches $PATH for ``name`` and
    returns a full path if found.

    If `all` is :const:`True` the set of all found locations is returned, else
    the first occurence or :const:`None` is returned.

    Args:
      `name` (str): The file to search for.
      `all` (bool):  Whether to return all locations where `name` was found.

    Returns:
      If `all` is :const:`True` the set of all locations where `name` was found,
      else the first location or :const:`None` if not found.

    Example:
      >>> which('sh')
      '/bin/sh'
"""
    isroot = os.getuid() == 0
    out = set()
    try:
        path = os.environ['PATH']
    except KeyError:
        log.exception('Environment variable $PATH is not set')
    for p in path.split(os.pathsep):
        p = os.path.join(p, name)
        if os.access(p, os.X_OK):
            st = os.stat(p)
            if not stat.S_ISREG(st.st_mode):
                continue
            # work around this issue: https://bugs.python.org/issue9311
            if isroot and not \
              st.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
                continue
            if all:
                out.add(p)
            else:
                return p
    if all:
        return out
    else:
        return None

def run_in_new_terminal(command, terminal = None, args = None):
    """run_in_new_terminal(command, terminal = None) -> None

    Run a command in a new terminal.

    If X11 is detected, the terminal will be launched with
    ``x-terminal-emulator``.

    If X11 is not detected, a new tmux pane is opened if possible.

    Args:
      command (str): The command to run.
      terminal (str): Which terminal to use.
      args (list): Arguments to pass to the terminal

    Returns:
      None
    """

    if not terminal:
        if 'XAUTHORITY' in os.environ:
            terminal = 'x-terminal-emulator'
            args     = ['-e']

        elif 'TMUX' in os.environ:
            terminal = 'tmux'
            args     = ['splitw']

    if not terminal:
        log.error('could not find terminal: %s' % terminal)

    argv    = [which(terminal)] + args + [command]
    log.debug("Launching a new terminal: %r" % argv)

    if os.fork() == 0:
        os.close(0)
        os.close(1)
        os.close(2)
        os.execv(argv[0], argv)
        os._exit(1)

def parse_ldd_output(output):
    """Parses the output from a run of 'ldd' on a binary.
    Returns a dictionary of {path: address} for
    each library required by the specified binary.

    Args:
      output(str): The output to parse

    Example:
        >>> sorted(parse_ldd_output('''
        ...     linux-vdso.so.1 =>  (0x00007fffbf5fe000)
        ...     libtinfo.so.5 => /lib/x86_64-linux-gnu/libtinfo.so.5 (0x00007fe28117f000)
        ...     libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007fe280f7b000)
        ...     libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fe280bb4000)
        ...     /lib64/ld-linux-x86-64.so.2 (0x00007fe2813dd000)
        ... ''').keys())
        ['/lib/x86_64-linux-gnu/libc.so.6', '/lib/x86_64-linux-gnu/libdl.so.2', '/lib/x86_64-linux-gnu/libtinfo.so.5', '/lib64/ld-linux-x86-64.so.2']
    """
    expr_linux   = re.compile(r'\s(?P<lib>\S?/\S+)\s+\((?P<addr>0x.+)\)')
    expr_openbsd = re.compile(r'^\s+(?P<addr>[0-9a-f]+)\s+[0-9a-f]+\s+\S+\s+[01]\s+[0-9]+\s+[0-9]+\s+(?P<lib>\S+)$')
    libs = {}

    for s in output.split('\n'):
        match = expr_linux.search(s) or expr_openbsd.search(s)
        if not match:
            continue
        lib, addr = match.group('lib'), match.group('addr')
        libs[lib] = int(addr, 16)

    return libs

def mkdir_p(path):
    """Emulates the behavior of ``mkdir -p``."""

    try:
        os.makedirs(path)
    except OSError as exc:
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise

def sh_string(s):
    """Outputs a string in a format that will be understood by /bin/sh.

    If the string does not contain any bad characters, it will simply be
    returned, possibly with quotes. If it contains bad characters, it will
    be escaped in a way which is compatible with most known systems.

    Examples:

        >>> print sh_string('foobar')
        foobar
        >>> print sh_string('foo bar')
        'foo bar'
        >>> print sh_string("foo'bar")
        "foo'bar"
        >>> print sh_string("foo\\\\bar")
        'foo\\bar'
        >>> print sh_string("foo\\\\'bar")
        "foo\\\\'bar"
        >>> print sh_string("foo\\x01'bar")
        "$( (echo Zm9vASdiYXI=|(base64 -d||openssl enc -d -base64)||echo -en 'foo\\x01\\x27bar') 2>/dev/null)"
        >>> print subprocess.check_output("echo -n " + sh_string("foo\\\\'bar"), shell = True)
        foo\\'bar
    """

    very_good = set(string.ascii_letters + string.digits)
    good      = (very_good | set(string.punctuation + ' ')) - set("'")
    alt_good  = (very_good | set(string.punctuation + ' ')) - set('!')

    if '\x00' in s:
        log.error("sh_string(): Cannot create a null-byte")

    if all(c in very_good for c in s):
        return s
    elif all(c in good for c in s):
        return "'%s'" % s
    elif all(c in alt_good for c in s):
        fixed = ''
        for c in s:
            if c in '"\\$`':
                fixed += '\\' + c
            else:
                fixed += c
        return '"%s"' % fixed
    else:
        fixed = ''
        for c in s:
            if c == '\\':
                fixed += '\\\\'
            elif c in good:
                fixed += c
            else:
                fixed += '\\x%02x' % ord(c)
        return '"$( (echo %s|(base64 -d||openssl enc -d -base64)||echo -en \'%s\') 2>/dev/null)"' % (base64.b64encode(s), fixed)

def register_sizes(regs, in_sizes):
    """Create dictionaries over register sizes and relations

    Given a list of lists of overlapping register names (e.g. ['eax','ax','al','ah']) and a list of input sizes,
    it returns the following:
      * all_regs    : list of all valid registers
      * sizes[reg]  : the size of reg in bits
      * bigger[reg] : list of overlapping registers bigger than reg
      * smaller[reg]: list of overlapping registers smaller than reg

    Used in i386/AMD64 shellcode, e.g. the mov-shellcode.

    Example:
        >>> regs = [['eax', 'ax', 'al', 'ah'],['ebx', 'bx', 'bl', 'bh'],
        ... ['ecx', 'cx', 'cl', 'ch'],
        ... ['edx', 'dx', 'dl', 'dh'],
        ... ['edi', 'di'],
        ... ['esi', 'si'],
        ... ['ebp', 'bp'],
        ... ['esp', 'sp'],
        ... ]
        >>> all_regs, sizes, bigger, smaller = register_sizes(regs, [32, 16, 8, 8])
        >>> all_regs
        ['eax', 'ax', 'al', 'ah', 'ebx', 'bx', 'bl', 'bh', 'ecx', 'cx', 'cl', 'ch', 'edx', 'dx', 'dl', 'dh', 'edi', 'di', 'esi', 'si', 'ebp', 'bp', 'esp', 'sp']
        >>> sizes
        {'ch': 8, 'cl': 8, 'ah': 8, 'edi': 32, 'al': 8, 'cx': 16, 'ebp': 32, 'ax': 16, 'edx': 32, 'ebx': 32, 'esp': 32, 'esi': 32, 'dl': 8, 'dh': 8, 'di': 16, 'bl': 8, 'bh': 8, 'eax': 32, 'bp': 16, 'dx': 16, 'bx': 16, 'ecx': 32, 'sp': 16, 'si': 16}
        >>> bigger
        {'ch': ['ecx', 'cx', 'ch'], 'cl': ['ecx', 'cx', 'cl'], 'ah': ['eax', 'ax', 'ah'], 'edi': ['edi'], 'al': ['eax', 'ax', 'al'], 'cx': ['ecx', 'cx'], 'ebp': ['ebp'], 'ax': ['eax', 'ax'], 'edx': ['edx'], 'ebx': ['ebx'], 'esp': ['esp'], 'esi': ['esi'], 'dl': ['edx', 'dx', 'dl'], 'dh': ['edx', 'dx', 'dh'], 'di': ['edi', 'di'], 'bl': ['ebx', 'bx', 'bl'], 'bh': ['ebx', 'bx', 'bh'], 'eax': ['eax'], 'bp': ['ebp', 'bp'], 'dx': ['edx', 'dx'], 'bx': ['ebx', 'bx'], 'ecx': ['ecx'], 'sp': ['esp', 'sp'], 'si': ['esi', 'si']}
        >>> smaller
        {'ch': [], 'cl': [], 'ah': [], 'edi': ['di'], 'al': [], 'cx': ['cl', 'ch'], 'ebp': ['bp'], 'ax': ['al', 'ah'], 'edx': ['dx', 'dl', 'dh'], 'ebx': ['bx', 'bl', 'bh'], 'esp': ['sp'], 'esi': ['si'], 'dl': [], 'dh': [], 'di': [], 'bl': [], 'bh': [], 'eax': ['ax', 'al', 'ah'], 'bp': [], 'dx': ['dl', 'dh'], 'bx': ['bl', 'bh'], 'ecx': ['cx', 'cl', 'ch'], 'sp': [], 'si': []}
    """
    sizes = {}
    bigger = {}
    smaller = {}

    for l in regs:
        for r, s in zip(l, in_sizes):
            sizes[r] = s

        for r in l:
            bigger[r] = [r_ for r_ in l if sizes[r_] > sizes[r] or r == r_]
            smaller[r] = [r_ for r_ in l if sizes[r_] < sizes[r]]

    return lists.concat(regs), sizes, bigger, smaller
