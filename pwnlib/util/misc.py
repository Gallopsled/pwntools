import base64
import errno
import os
import platform
import re
import socket
import stat
import string

from pwnlib.context import context
from pwnlib.log import getLogger
from pwnlib.util import fiddling
from pwnlib.util import lists

log = getLogger(__name__)

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


def size(n, abbrev = 'B', si = False):
    """size(n, abbrev = 'B', si = False) -> str

    Convert the length of a bytestream to human readable form.

    Arguments:
      n(int,iterable): The length to convert to human readable form,
        or an object which can have ``len()`` called on it.
      abbrev(str): String appended to the size, defaults to ``'B'``.

    Example:
        >>> size(451)
        '451B'
        >>> size(1000)
        '1000B'
        >>> size(1024)
        '1.00KB'
        >>> size(1024, ' bytes')
        '1.00K bytes'
        >>> size(1024, si = True)
        '1.02KB'
        >>> [size(1024 ** n) for n in range(7)]
        ['1B', '1.00KB', '1.00MB', '1.00GB', '1.00TB', '1.00PB', '1024.00PB']
        >>> size([])
        '0B'
        >>> size([1,2,3])
        '3B'
    """
    if hasattr(n, '__len__'):
        n = len(n)

    base = 1000.0 if si else 1024.0
    if n < base:
        return '%d%s' % (n, abbrev)

    for suffix in ['K', 'M', 'G', 'T']:
        n /= base
        if n < base:
            return '%.02f%s%s' % (n, suffix, abbrev)

    return '%.02fP%s' % (n / base, abbrev)

KB = 1024
MB = 1024 * KB
GB = 1024 * MB

KiB = 1000
MiB = 1000 * KB
GiB = 1000 * MB

def read(path, count=-1, skip=0):
    r"""read(path, count=-1, skip=0) -> str

    Open file, return content.

    Examples:
        >>> read('/proc/self/exe')[:4]
        '\x7fELF'
    """
    path = os.path.expanduser(os.path.expandvars(path))
    with open(path) as fd:
        if skip:
            fd.seek(skip)
        return fd.read(count)


def write(path, data = '', create_dir = False, mode = 'w'):
    """Create new file or truncate existing to zero length and write data."""
    path = os.path.expanduser(os.path.expandvars(path))
    if create_dir:
        path = os.path.realpath(path)
        mkdir_p(os.path.dirname(path))
    with open(path, mode) as f:
        f.write(data)

def which(name, all = False):
    """which(name, flags = os.X_OK, all = False) -> str or str set

    Works as the system command ``which``; searches $PATH for ``name`` and
    returns a full path if found.

    If `all` is :const:`True` the set of all found locations is returned, else
    the first occurence or :const:`None` is returned.

    Arguments:
      `name` (str): The file to search for.
      `all` (bool):  Whether to return all locations where `name` was found.

    Returns:
      If `all` is :const:`True` the set of all locations where `name` was found,
      else the first location or :const:`None` if not found.

    Example:
      >>> which('sh')
      '/bin/sh'
"""
    # If name is a path, do not attempt to resolve it.
    if os.path.sep in name:
        return name

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

    When ``terminal`` is not set:
        - If ``context.terminal`` is set it will be used.
          If it is an iterable then ``context.terminal[1:]`` are default arguments.
        - If a ``pwntools-terminal`` command exists in ``$PATH``, it is used
        - If ``$TERM_PROGRAM`` is set, that is used.
        - If X11 is detected (by the presence of the ``$DISPLAY`` environment
          variable), ``x-terminal-emulator`` is used.
        - If tmux is detected (by the presence of the ``$TMUX`` environment
          variable), a new pane will be opened.

    Arguments:
        command (str): The command to run.
        terminal (str): Which terminal to use.
        args (list): Arguments to pass to the terminal

    Note:
        The command is opened with ``/dev/null`` for stdin, stdout, stderr.

    Returns:
      PID of the new terminal process
    """

    if not terminal:
        if context.terminal:
            terminal = context.terminal[0]
            args     = context.terminal[1:]
        elif which('pwntools-terminal'):
            terminal = 'pwntools-terminal'
            args     = []
        elif 'TERM_PROGRAM' in os.environ:
            terminal = os.environ['TERM_PROGRAM']
            args     = []
        elif 'DISPLAY' in os.environ and which('x-terminal-emulator'):
            terminal = 'x-terminal-emulator'
            args     = ['-e']
        elif 'TMUX' in os.environ and which('tmux'):
            terminal = 'tmux'
            args     = ['splitw']

    if not terminal:
        log.error('Could not find a terminal binary to use. Set context.terminal to your terminal.')
    elif not which(terminal):
        log.error('Could not find terminal binary %r. Set context.terminal to your terminal.' % terminal)

    if isinstance(args, tuple):
        args = list(args)

    argv = [which(terminal)] + args

    if isinstance(command, str):
        if ';' in command:
            log.error("Cannot use commands with semicolon.  Create a script and invoke that directly.")
        argv += [command]
    elif isinstance(command, (list, tuple)):
        if any(';' in c for c in command):
            log.error("Cannot use commands with semicolon.  Create a script and invoke that directly.")
        argv += list(command)

    log.debug("Launching a new terminal: %r" % argv)

    pid = os.fork()

    if pid == 0:
        # Closing the file descriptors makes everything fail under tmux on OSX.
        if platform.system() != 'Darwin':
            devnull = open(os.devnull, 'rwb')
            os.dup2(devnull.fileno(), 0)
            os.dup2(devnull.fileno(), 1)
            os.dup2(devnull.fileno(), 2)
        os.execv(argv[0], argv)
        os._exit(1)

    return pid

def parse_ldd_output(output):
    """Parses the output from a run of 'ldd' on a binary.
    Returns a dictionary of {path: address} for
    each library required by the specified binary.

    Arguments:
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

def dealarm_shell(tube):
    """Given a tube which is a shell, dealarm it.
    """
    tube.clean()

    tube.sendline('which python || echo')
    if tube.recvline().startswith('/'):
        tube.sendline('''exec python -c "import signal, os; signal.alarm(0); os.execl('$SHELL','')"''')
        return tube

    tube.sendline('which perl || echo')
    if tube.recvline().startswith('/'):
        tube.sendline('''exec perl -e "alarm 0; exec '${SHELL:-/bin/sh}'"''')
        return tube

    return None

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
