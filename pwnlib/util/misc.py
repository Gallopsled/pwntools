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
import inspect
import types

from pwnlib import atexit
from pwnlib.context import context
from pwnlib.log import getLogger
from pwnlib.util import fiddling
from pwnlib.util import lists
from pwnlib.util import packing

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

KB = 1000
MB = 1000 * KB
GB = 1000 * MB

KiB = 1024
MiB = 1024 * KiB
GiB = 1024 * MiB

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
    Tries all of the file extensions in $PATHEXT on Windows too.

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

    if sys.platform == 'win32':
        pathexts = os.environ.get('PATHEXT', '').split(os.pathsep)
        isroot = False
    else:
        pathexts = []
        isroot = os.getuid() == 0
    pathexts = [''] + pathexts
    out = set()
    try:
        path = path or os.environ['PATH']
    except KeyError:
        log.exception('Environment variable $PATH is not set')
    for path_part in path.split(os.pathsep):
        for ext in pathexts:
            nameext = name + ext
            p = os.path.join(path_part, nameext)
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
                    break
                else:
                    return p
    if all:
        return out
    else:
        return None


def normalize_argv_env(argv, env, log, level=2):
    #
    # Validate argv
    #
    # - Must be a list/tuple of strings
    # - Each string must not contain '\x00'
    #
    argv = argv or []
    if isinstance(argv, (six.text_type, six.binary_type)):
        argv = [argv]

    if not isinstance(argv, (list, tuple)):
        log.error('argv must be a list or tuple: %r' % argv)

    if not all(isinstance(arg, (six.text_type, bytes, bytearray)) for arg in argv):
        log.error("argv must be strings or bytes: %r" % argv)

    # Create a duplicate so we can modify it
    argv = list(argv)

    for i, oarg in enumerate(argv):
        arg = packing._need_bytes(oarg, level, 0x80)  # ASCII text is okay
        if b'\x00' in arg[:-1]:
            log.error('Inappropriate nulls in argv[%i]: %r' % (i, oarg))
        argv[i] = bytearray(arg.rstrip(b'\x00'))

    #
    # Validate environment
    #
    # - Must be a dictionary of {string:string}
    # - No strings may contain '\x00'
    #

    # Create a duplicate so we can modify it safely
    env2 = []
    if hasattr(env, 'items'):
        env_items = env.items()
    else:
        env_items = env
    if env:
        for k,v in env_items:
            if not isinstance(k, (bytes, six.text_type)):
                log.error('Environment keys must be strings: %r' % k)
            # Check if = is in the key, Required check since we sometimes call ctypes.execve directly
            # https://github.com/python/cpython/blob/025995feadaeebeef5d808f2564f0fd65b704ea5/Modules/posixmodule.c#L6476
            if b'=' in packing._encode(k):
                log.error('Environment keys may not contain "=": %r' % (k))
            if not isinstance(v, (bytes, six.text_type)):
                log.error('Environment values must be strings: %r=%r' % (k,v))
            k = packing._need_bytes(k, level, 0x80)  # ASCII text is okay
            v = packing._need_bytes(v, level, 0x80)  # ASCII text is okay
            if b'\x00' in k[:-1]:
                log.error('Inappropriate nulls in env key: %r' % (k))
            if b'\x00' in v[:-1]:
                log.error('Inappropriate nulls in env value: %r=%r' % (k, v))
            env2.append((bytearray(k.rstrip(b'\x00')), bytearray(v.rstrip(b'\x00'))))

    return argv, env2 or env


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
        - If KDE Konsole is detected (by the presence of the ``$KONSOLE_VERSION``
          environment variable), a terminal will be split.
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
        elif 'TERM_PROGRAM' in os.environ and os.environ['TERM_PROGRAM'] == "iTerm.app" and which('osascript'):
            # if we're on a mac, and using iTerm
            terminal = "osascript"
            args     = []
        elif 'TERM_PROGRAM' in os.environ and which(os.environ['TERM_PROGRAM']):
            terminal = os.environ['TERM_PROGRAM']
            args     = []
        elif 'DISPLAY' in os.environ and which('x-terminal-emulator'):
            terminal = 'x-terminal-emulator'
            args     = ['-e']
        elif 'KONSOLE_VERSION' in os.environ and which('qdbus'):
            qdbus = which('qdbus')
            window_id = os.environ['WINDOWID']
            konsole_dbus_service = os.environ['KONSOLE_DBUS_SERVICE']

            with subprocess.Popen((qdbus, konsole_dbus_service), stdout=subprocess.PIPE) as proc:
                lines = proc.communicate()[0].decode().split('\n')

            # Iterate over all MainWindows
            for line in lines:
                parts = line.split('/')
                if len(parts) == 3 and parts[2].startswith('MainWindow_'):
                    name = parts[2]
                    with subprocess.Popen((qdbus, konsole_dbus_service, '/konsole/' + name,
                                           'org.kde.KMainWindow.winId'), stdout=subprocess.PIPE) as proc:
                        target_window_id = proc.communicate()[0].decode().strip()
                        if target_window_id == window_id:
                            break
            else:
                log.error('MainWindow not found')

            # Split
            subprocess.run((qdbus, konsole_dbus_service, '/konsole/' + name,
                            'org.kde.KMainWindow.activateAction', 'split-view-left-right'), stdout=subprocess.DEVNULL)

            # Find new session
            with subprocess.Popen((qdbus, konsole_dbus_service, os.environ['KONSOLE_DBUS_WINDOW'],
                                   'org.kde.konsole.Window.sessionList'), stdout=subprocess.PIPE) as proc:
                session_list = map(int, proc.communicate()[0].decode().split())
            last_konsole_session = max(session_list)

            terminal = 'qdbus'
            args = [konsole_dbus_service, '/Sessions/{}'.format(last_konsole_session),
                    'org.kde.konsole.Session.runCommand']

        else:
            is_wsl = False
            if os.path.exists('/proc/sys/kernel/osrelease'):
                with open('/proc/sys/kernel/osrelease', 'rb') as f:
                    is_wsl = b'icrosoft' in f.read()
            if is_wsl and which('cmd.exe') and which('wsl.exe') and which('bash.exe'):
                terminal    = 'cmd.exe'
                args        = ['/c', 'start']
                distro_name = os.getenv('WSL_DISTRO_NAME')

                # Split pane in Windows Terminal
                if 'WT_SESSION' in os.environ and which('wt.exe'):
                    args.extend(['wt.exe', '-w', '0', 'split-pane', '-d', '.'])

                if distro_name:
                    args.extend(['wsl.exe', '-d', distro_name, 'bash', '-c'])
                else:
                    args.extend(['bash.exe', '-c'])

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
        script = script.format(executable='/bin/env ' * (' ' in sys.executable) + sys.executable,
                               argv=command,
                               argv0=which(command[0]))
        script = script.lstrip()

        log.debug("Created script for new terminal:\n%s" % script)

        with tempfile.NamedTemporaryFile(delete=False, mode='wt+') as tmp:
          tmp.write(script)
          tmp.flush()
          os.chmod(tmp.name, 0o700)
          argv += [tmp.name]


    # if we're on a Mac and use iTerm, we use `osascript` to split the current window
    # `command` was sanitized on the previous step. It is now either a string, or was written to a tmp file
    # we run the command, which is now `argv[-1]`
    if terminal == 'osascript':
        osa_script = """
tell application "iTerm"
    tell current session of current window
        set newSession to (split horizontally with default profile)
    end tell
    tell newSession
        write text "{}"
    end tell
end tell
""".format(argv[-1])
        with tempfile.NamedTemporaryFile(delete=False, mode='wt+') as tmp:
            tmp.write(osa_script.lstrip())
            tmp.flush()
            os.chmod(tmp.name, 0o700)
            argv = [which(terminal), tmp.name]

    log.debug("Launching a new terminal: %r" % argv)

    stdin = stdout = stderr = open(os.devnull, 'r+b')
    if terminal == 'tmux':
        stdout = subprocess.PIPE

    p = subprocess.Popen(argv, stdin=stdin, stdout=stdout, stderr=stderr, preexec_fn=preexec_fn)

    if terminal == 'tmux':
        out, _ = p.communicate()
        try:
            pid = int(out)
        except ValueError:
            pid = None
        if pid is None:
            log.error("Could not parse PID from tmux output (%r). Start tmux first.", out)
    elif terminal == 'qdbus':
        with subprocess.Popen((qdbus, konsole_dbus_service, '/Sessions/{}'.format(last_konsole_session),
                               'org.kde.konsole.Session.processId'), stdout=subprocess.PIPE) as proc:
            pid = int(proc.communicate()[0].decode())
    else:
        pid = p.pid

    if kill_at_exit:
        def kill():
            try:
                if terminal == 'qdbus':
                    os.kill(pid, signal.SIGHUP)
                else:
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

def _create_execve_script(argv=None, executable=None, cwd=None, env=None, ignore_environ=None,
        stdin=0, stdout=1, stderr=2, preexec_fn=None, preexec_args=(), aslr=None, setuid=None,
        shell=False, log=log):
    """
    Creates a python wrapper script that triggers the syscall `execve` directly.

    Arguments:
        argv(list):
            List of arguments to pass into the process
        executable(str):
            Path to the executable to run.
            If :const:`None`, ``argv[0]`` is used.
        cwd(str):
            Working directory.  If :const:`None`, uses the working directory specified
            on :attr:`cwd` or set via :meth:`set_working_directory`.
        env(dict):
            Environment variables to add to the environment.
        ignore_environ(bool):
            Ignore default environment.  By default use default environment iff env not specified.
        stdin(int, str):
            If an integer, replace stdin with the numbered file descriptor.
            If a string, a open a file with the specified path and replace
            stdin with its file descriptor.  May also be one of ``sys.stdin``,
            ``sys.stdout``, ``sys.stderr``.  If :const:`None`, the file descriptor is closed.
        stdout(int, str):
            See ``stdin``.
        stderr(int, str):
            See ``stdin``.
        preexec_fn(callable):
            Function which is executed on the remote side before execve().
            This **MUST** be a self-contained function -- it must perform
            all of its own imports, and cannot refer to variables outside
            its scope.
        preexec_args(object):
            Argument passed to ``preexec_fn``.
            This **MUST** only consist of native Python objects.
        aslr(bool):
            See :class:`pwnlib.tubes.process.process` for more information.
        setuid(bool):
            See :class:`pwnlib.tubes.process.process` for more information.
        shell(bool):
            Pass the command-line arguments to the shell.

    Returns:
        A string containing the python script.
    """
    if not argv and not executable:
        log.error("Must specify argv or executable")

    aslr      = aslr if aslr is not None else context.aslr

    if ignore_environ is None:
        ignore_environ = env is not None  # compat

    argv, env = normalize_argv_env(argv, env, log)

    if shell:
        if len(argv) != 1:
            log.error('Cannot provide more than 1 argument if shell=True')
        argv = [bytearray(b'/bin/sh'), bytearray(b'-c')] + argv

    executable = executable or argv[0]
    cwd        = cwd or '.'

    # Validate, since failures on the remote side will suck.
    if not isinstance(executable, (six.text_type, six.binary_type, bytearray)):
        log.error("executable / argv[0] must be a string: %r" % executable)
    executable = bytearray(packing._need_bytes(executable, min_wrong=0x80))

    # Allow passing in sys.stdin/stdout/stderr objects
    handles = {sys.stdin: 0, sys.stdout:1, sys.stderr:2}
    stdin  = handles.get(stdin, stdin)
    stdout = handles.get(stdout, stdout)
    stderr = handles.get(stderr, stderr)

    # Allow the user to provide a self-contained function to run
    def func(): pass
    func      = preexec_fn or func
    func_args = preexec_args

    if not isinstance(func, types.FunctionType):
        log.error("preexec_fn must be a function")

    func_name = func.__name__
    if func_name == (lambda: 0).__name__:
        log.error("preexec_fn cannot be a lambda")

    func_src  = inspect.getsource(func).strip()
    setuid = True if setuid is None else bool(setuid)


    script = r"""
#!/usr/bin/env python
import os, sys, ctypes, resource, platform, stat
from collections import OrderedDict
try:
    integer_types = int, long
except NameError:
    integer_types = int,
exe   = bytes(%(executable)r)
argv  = [bytes(a) for a in %(argv)r]
env   = %(env)r

os.chdir(%(cwd)r)

if %(ignore_environ)r:
    os.environ.clear()

environ = getattr(os, 'environb', os.environ)

if env is not None:
    env = OrderedDict((bytes(k), bytes(v)) for k,v in env)
    environ.update(env)
else:
    env = environ

def is_exe(path):
    return os.path.isfile(path) and os.access(path, os.X_OK)

PATH = environ.get(b'PATH',b'').split(os.pathsep.encode())

if os.path.sep.encode() not in exe and not is_exe(exe):
    for path in PATH:
        test_path = os.path.join(path, exe)
        if is_exe(test_path):
            exe = test_path
            break

if not is_exe(exe):
    sys.stderr.write('3\n')
    sys.stderr.write("{!r} is not executable or does not exist in $PATH: {!r}".format(exe,PATH))
    sys.exit(-1)

if not %(setuid)r:
    PR_SET_NO_NEW_PRIVS = 38
    result = ctypes.CDLL('libc.so.6').prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)

    if result != 0:
        sys.stdout.write('3\n')
        sys.stdout.write("Could not disable setuid: prctl(PR_SET_NO_NEW_PRIVS) failed")
        sys.exit(-1)

try:
    PR_SET_PTRACER = 0x59616d61
    PR_SET_PTRACER_ANY = -1
    ctypes.CDLL('libc.so.6').prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0)
except Exception:
    pass

# Determine what UID the process will execute as
# This is used for locating apport core dumps
suid = os.getuid()
sgid = os.getgid()
st = os.stat(exe)
if %(setuid)r:
    if (st.st_mode & stat.S_ISUID):
        suid = st.st_uid
    if (st.st_mode & stat.S_ISGID):
        sgid = st.st_gid

if sys.argv[-1] == 'check':
    sys.stdout.write("1\n")
    sys.stdout.write(str(os.getpid()) + "\n")
    sys.stdout.write(str(os.getuid()) + "\n")
    sys.stdout.write(str(os.getgid()) + "\n")
    sys.stdout.write(str(suid) + "\n")
    sys.stdout.write(str(sgid) + "\n")
    getattr(sys.stdout, 'buffer', sys.stdout).write(os.path.realpath(exe) + b'\x00')
    sys.stdout.flush()

for fd, newfd in {0: %(stdin)r, 1: %(stdout)r, 2:%(stderr)r}.items():
    if newfd is None:
        os.close(fd)
    elif isinstance(newfd, (str, bytes)):
        newfd = os.open(newfd, os.O_RDONLY if fd == 0 else (os.O_RDWR|os.O_CREAT))
        os.dup2(newfd, fd)
        os.close(newfd)
    elif isinstance(newfd, integer_types) and newfd != fd:
        os.dup2(fd, newfd)

if not %(aslr)r:
    if platform.system().lower() == 'linux' and %(setuid)r is not True:
        ADDR_NO_RANDOMIZE = 0x0040000
        ctypes.CDLL('libc.so.6').personality(ADDR_NO_RANDOMIZE)

    resource.setrlimit(resource.RLIMIT_STACK, (-1, -1))

# Attempt to dump ALL core file regions
try:
    with open('/proc/self/coredump_filter', 'w') as core_filter:
        core_filter.write('0x3f\n')
except Exception:
    pass

# Assume that the user would prefer to have core dumps.
try:
    resource.setrlimit(resource.RLIMIT_CORE, (-1, -1))
except Exception:
    pass

%(func_src)s
%(func_name)s(*%(func_args)r)

""" % locals()  

    if len(argv) > 0 and len(argv[0]) > 0:
        script += r"os.execve(exe, argv, env) " 

    # os.execve does not allow us to pass empty argv[0]
    # Therefore we use ctypes to call execve directly
    else:
        script += r"""
# Transform envp from dict to list
env_list = [key + b"=" + value for key, value in env.items()]

# ctypes helper to convert a python list to a NULL-terminated C array
def to_carray(py_list):
    py_list += [None] # NULL-terminated
    return (ctypes.c_char_p * len(py_list))(*py_list)

c_argv = to_carray(argv)
c_env = to_carray(env_list)

# Call execve
libc = ctypes.CDLL('libc.so.6')
libc.execve(exe, c_argv, c_env)

# We should never get here, since we sanitized argv and env,
# but just in case, indicate that something went wrong.
libc.perror(b"execve")
raise OSError("execve failed")
""" % locals()
    script = script.strip()

    return script
