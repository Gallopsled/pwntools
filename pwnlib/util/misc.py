from __future__ import division

import base64
import errno
import os
import re
import signal
import six
import socket
import stat
import string
import subprocess
import sys
import tempfile

from pwnlib import atexit
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
    return x + -x % alignment


def align_down(alignment, x):
    """align_down(alignment, x) -> int

    Rounds `x` down to nearest multiple of the `alignment`.

    Example:
        >>> [align_down(5, n) for n in range(15)]
        [0, 0, 0, 0, 0, 5, 5, 5, 5, 5, 10, 10, 10, 10, 10]
    """
    return x - x % alignment


def binary_ip(host):
    """binary_ip(host) -> str

    Resolve host and return IP as four byte string.

    Example:
        >>> binary_ip("127.0.0.1")
        b'\\x7f\\x00\\x00\\x01'
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
        b'\x7fELF'
    """
    path = os.path.expanduser(os.path.expandvars(path))
    with open(path, 'rb') as fd:
        if skip:
            fd.seek(skip)
        return fd.read(count)


def write(path, data = b'', create_dir = False, mode = 'w'):
    """Create new file or truncate existing to zero length and write data."""
    path = os.path.expanduser(os.path.expandvars(path))
    if create_dir:
        path = os.path.realpath(path)
        mkdir_p(os.path.dirname(path))
    if mode == 'w' and isinstance(data, bytes): mode += 'b'
    with open(path, mode) as f:
        f.write(data)

def which(name, all = False, path=None):
    """which(name, flags = os.X_OK, all = False) -> str or str set

    Works as the system command ``which``; searches $PATH for ``name`` and
    returns a full path if found.

    If `all` is :const:`True` the set of all found locations is returned, else
    the first occurrence or :const:`None` is returned.

    Arguments:
      `name` (str): The file to search for.
      `all` (bool):  Whether to return all locations where `name` was found.

    Returns:
      If `all` is :const:`True` the set of all locations where `name` was found,
      else the first location or :const:`None` if not found.

    Example:

        >>> which('sh') # doctest: +ELLIPSIS
        '.../bin/sh'
    """
    # If name is a path, do not attempt to resolve it.
    if os.path.sep in name:
        return name

    isroot = os.getuid() == 0
    out = set()
    try:
        path = path or os.environ['PATH']
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

def run_in_new_terminal(command, terminal=None, args=None, kill_at_exit=True, preexec_fn=None):
    """run_in_new_terminal(command, terminal=None, args=None, kill_at_exit=True, preexec_fn=None) -> int

    Run a command in a new terminal.

    When ``terminal`` is not set:
        - If ``context.terminal`` is set it will be used.
          If it is an iterable then ``context.terminal[1:]`` are default arguments.
        - If a ``pwntools-terminal`` command exists in ``$PATH``, it is used
        - If tmux is detected (by the presence of the ``$TMUX`` environment
          variable), a new pane will be opened.
        - If GNU Screen is detected (by the presence of the ``$STY`` environment
          variable), a new screen will be opened.
        - If ``$TERM_PROGRAM`` is set, that is used.
        - If X11 is detected (by the presence of the ``$DISPLAY`` environment
          variable), ``x-terminal-emulator`` is used.
        - If WSL (Windows Subsystem for Linux) is detected (by the presence of
          a ``wsl.exe`` binary in the ``$PATH`` and ``/proc/sys/kernel/osrelease``
          containing ``Microsoft``), a new ``cmd.exe`` window will be opened.

    If `kill_at_exit` is :const:`True`, try to close the command/terminal when the
    current process exits. This may not work for all terminal types.

    Arguments:
        command (str): The command to run.
        terminal (str): Which terminal to use.
        args (list): Arguments to pass to the terminal
        kill_at_exit (bool): Whether to close the command/terminal on process exit.
        preexec_fn (callable): Callable to invoke before exec().

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
        elif 'TMUX' in os.environ and which('tmux'):
            terminal = 'tmux'
            args     = ['splitw']
        elif 'STY' in os.environ and which('screen'):
            terminal = 'screen'
            args     = ['-t','pwntools-gdb','bash','-c']
        elif 'TERM_PROGRAM' in os.environ:
            terminal = os.environ['TERM_PROGRAM']
            args     = []
        elif 'DISPLAY' in os.environ and which('x-terminal-emulator'):
            terminal = 'x-terminal-emulator'
            args     = ['-e']
        else:
            is_wsl = False
            if os.path.exists('/proc/sys/kernel/osrelease'):
                with open('/proc/sys/kernel/osrelease', 'rb') as f:
                    is_wsl = b'icrosoft' in f.read()
            if is_wsl and which('cmd.exe') and which('wsl.exe') and which('bash.exe'):
                terminal = 'cmd.exe'
                args     = ['/c', 'start', 'bash.exe', '-c']

    if not terminal:
        log.error('Could not find a terminal binary to use. Set context.terminal to your terminal.')
    elif not which(terminal):
        log.error('Could not find terminal binary %r. Set context.terminal to your terminal.' % terminal)

    if isinstance(args, tuple):
        args = list(args)

    # When not specifying context.terminal explicitly, we used to set these flags above.
    # However, if specifying terminal=['tmux', 'splitw', '-h'], we would be lacking these flags.
    # Instead, set them here and hope for the best.
    if terminal == 'tmux':
        args += ['-F' '#{pane_pid}', '-P']

    argv = [which(terminal)] + args

    if isinstance(command, six.string_types):
        if ';' in command:
            log.error("Cannot use commands with semicolon.  Create a script and invoke that directly.")
        argv += [command]
    elif isinstance(command, (list, tuple)):
        # Dump the full command line to a temporary file so we can be sure that
        # it is parsed correctly, and we do not need to account for shell expansion
        script = '''
#!{executable!s}
import os
os.execve({argv0!r}, {argv!r}, os.environ)
'''
        script = script.format(executable=sys.executable,
                               argv=command,
                               argv0=which(command[0]))
        script = script.lstrip()

        log.debug("Created script for new terminal:\n%s" % script)

        with tempfile.NamedTemporaryFile(delete=False, mode='wt+') as tmp:
          tmp.write(script)
          tmp.flush()
          os.chmod(tmp.name, 0o700)
          argv += [tmp.name]


    log.debug("Launching a new terminal: %r" % argv)

    stdin = stdout = stderr = open(os.devnull, 'r+b')
    if terminal == 'tmux':
        stdout = subprocess.PIPE

    p = subprocess.Popen(argv, stdin=stdin, stdout=stdout, stderr=stderr, preexec_fn=preexec_fn)

    if terminal == 'tmux':
        out, _ = p.communicate()
        pid = int(out)
    else:
        pid = p.pid

    if kill_at_exit:
        def kill():
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError:
                pass

        atexit.register(kill)

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
        >>> pprint(sizes)
        {'ah': 8,
         'al': 8,
         'ax': 16,
         'bh': 8,
         'bl': 8,
         'bp': 16,
         'bx': 16,
         'ch': 8,
         'cl': 8,
         'cx': 16,
         'dh': 8,
         'di': 16,
         'dl': 8,
         'dx': 16,
         'eax': 32,
         'ebp': 32,
         'ebx': 32,
         'ecx': 32,
         'edi': 32,
         'edx': 32,
         'esi': 32,
         'esp': 32,
         'si': 16,
         'sp': 16}
        >>> pprint(bigger)
        {'ah': ['eax', 'ax', 'ah'],
         'al': ['eax', 'ax', 'al'],
         'ax': ['eax', 'ax'],
         'bh': ['ebx', 'bx', 'bh'],
         'bl': ['ebx', 'bx', 'bl'],
         'bp': ['ebp', 'bp'],
         'bx': ['ebx', 'bx'],
         'ch': ['ecx', 'cx', 'ch'],
         'cl': ['ecx', 'cx', 'cl'],
         'cx': ['ecx', 'cx'],
         'dh': ['edx', 'dx', 'dh'],
         'di': ['edi', 'di'],
         'dl': ['edx', 'dx', 'dl'],
         'dx': ['edx', 'dx'],
         'eax': ['eax'],
         'ebp': ['ebp'],
         'ebx': ['ebx'],
         'ecx': ['ecx'],
         'edi': ['edi'],
         'edx': ['edx'],
         'esi': ['esi'],
         'esp': ['esp'],
         'si': ['esi', 'si'],
         'sp': ['esp', 'sp']}
        >>> pprint(smaller)
        {'ah': [],
         'al': [],
         'ax': ['al', 'ah'],
         'bh': [],
         'bl': [],
         'bp': [],
         'bx': ['bl', 'bh'],
         'ch': [],
         'cl': [],
         'cx': ['cl', 'ch'],
         'dh': [],
         'di': [],
         'dl': [],
         'dx': ['dl', 'dh'],
         'eax': ['ax', 'al', 'ah'],
         'ebp': ['bp'],
         'ebx': ['bx', 'bl', 'bh'],
         'ecx': ['cx', 'cl', 'ch'],
         'edi': ['di'],
         'edx': ['dx', 'dl', 'dh'],
         'esi': ['si'],
         'esp': ['sp'],
         'si': [],
         'sp': []}
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


def python_2_bytes_compatible(klass):
    """
    A class decorator that defines __str__ methods under Python 2.
    Under Python 3 it does nothing.
    """
    if six.PY2:
        if '__str__' not in klass.__dict__:
            klass.__str__ = klass.__bytes__
    return klass
