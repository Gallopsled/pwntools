from __future__ import absolute_import
from __future__ import division

import errno
import socket
import time

import psutil

from pwnlib import tubes
from pwnlib.log import getLogger
from .net import sock_match
from pwnlib.timeout import Timeout

log = getLogger(__name__)

all_pids = psutil.pids

def pidof(target):
    """pidof(target) -> int list

    Get PID(s) of `target`.  The returned PID(s) depends on the type of `target`:

    - :class:`str`: PIDs of all processes with a name matching `target`.
    - :class:`pwnlib.tubes.process.process`: singleton list of the PID of `target`.
    - :class:`pwnlib.tubes.sock.sock`: singleton list of the PID at the
      remote end of `target` if it is running on the host.  Otherwise an
      empty list.

    Arguments:
        target(object):  The target whose PID(s) to find.

    Returns:
        A list of found PIDs.

    Example:
        >>> l = tubes.listen.listen()
        >>> p = process(['curl', '-s', 'http://127.0.0.1:%d'%l.lport])
        >>> pidof(p) == pidof(l) == pidof(('127.0.0.1', l.lport))
        True
    """
    if isinstance(target, tubes.ssh.ssh_channel):
        return [target.pid]

    elif isinstance(target, tubes.sock.sock):
        local  = target.sock.getsockname()
        remote = target.sock.getpeername()
        match = sock_match(remote, local, target.family, target.type)
        return [c.pid for c in psutil.net_connections() if match(c)]

    elif isinstance(target, tuple):
        match = sock_match(None, target)
        return [c.pid for c in psutil.net_connections() if match(c)]

    elif isinstance(target, tubes.process.process):
        return [target.proc.pid]

    else:
        return pid_by_name(target)

def pid_by_name(name):
    """pid_by_name(name) -> int list

    Arguments:
        name (str): Name of program.

    Returns:
        List of PIDs matching `name` sorted by lifetime, youngest to oldest.

    Example:
        >>> os.getpid() in pid_by_name(name(os.getpid()))
        True
    """
    def match(p):
        if p.status() == 'zombie':
            return False
        if p.name() == name:
            return True
        try:
            if p.exe() == name:
                return True
        except Exception:
            pass
        return False

    processes = (p for p in psutil.process_iter() if match(p))

    processes = sorted(processes, key=lambda p: p.create_time(), reverse=True)

    return [p.pid for p in processes]

def name(pid):
    """name(pid) -> str

    Arguments:
        pid (int): PID of the process.

    Returns:
        Name of process as listed in ``/proc/<pid>/status``.

    Example:
        >>> p = process('cat')
        >>> name(p.pid)
        'cat'
    """
    return psutil.Process(pid).name()

def parent(pid):
    """parent(pid) -> int

    Arguments:
        pid (int): PID of the process.

    Returns:
        Parent PID as listed in ``/proc/<pid>/status`` under ``PPid``,
        or 0 if there is not parent.
    """
    try:
         return psutil.Process(pid).parent().pid
    except Exception:
         return 0

def children(ppid):
    """children(ppid) -> int list

    Arguments:
        pid (int): PID of the process.

    Returns:
        List of PIDs of whose parent process is `pid`.
    """
    return [p.pid for p in psutil.Process(ppid).children()]

def ancestors(pid):
    """ancestors(pid) -> int list

    Arguments:
        pid (int): PID of the process.

    Returns:
        List of PIDs of whose parent process is `pid` or an ancestor of `pid`.

    Example:
        >>> ancestors(os.getpid()) # doctest: +ELLIPSIS
        [..., 1]
    """
    pids = []
    while pid != 0:
         pids.append(pid)
         pid = parent(pid)
    return pids

def descendants(pid):
    """descendants(pid) -> dict

    Arguments:
        pid (int): PID of the process.

    Returns:
        Dictionary mapping the PID of each child of `pid` to it's descendants.

    Example:
        >>> d = descendants(os.getppid())
        >>> os.getpid() in d.keys()
        True
    """
    this_pid = pid
    allpids = all_pids()
    ppids = {}
    def _parent(pid):
         if pid not in ppids:
             ppids[pid] = parent(pid)
         return ppids[pid]
    def _children(ppid):
         return [pid for pid in allpids if _parent(pid) == ppid]
    def _loop(ppid):
         return {pid: _loop(pid) for pid in _children(ppid)}
    return _loop(pid)

def exe(pid):
    """exe(pid) -> str

    Arguments:
        pid (int): PID of the process.

    Returns:
        The path of the binary of the process. I.e. what ``/proc/<pid>/exe`` points to.

    Example:
        >>> exe(os.getpid()) == os.path.realpath(sys.executable)
        True
    """
    return psutil.Process(pid).exe()

def cwd(pid):
    """cwd(pid) -> str

    Arguments:
        pid (int): PID of the process.

    Returns:
        The path of the process's current working directory. I.e. what
        ``/proc/<pid>/cwd`` points to.

    Example:
        >>> cwd(os.getpid()) == os.getcwd()
        True
    """
    return psutil.Process(pid).cwd()

def cmdline(pid):
    """cmdline(pid) -> str list

    Arguments:
        pid (int): PID of the process.

    Returns:
        A list of the fields in ``/proc/<pid>/cmdline``.

    Example:
        >>> 'py' in ''.join(cmdline(os.getpid()))
        True
    """
    return psutil.Process(pid).cmdline()

def stat(pid):
    """stat(pid) -> str list

    Arguments:
        pid (int): PID of the process.

    Returns:
        A list of the values in ``/proc/<pid>/stat``, with the exception that ``(`` and ``)`` has been removed from around the process name.

    Example:
        >>> stat(os.getpid())[2]
        'R'
    """
    with open('/proc/%d/stat' % pid) as fd:
         s = fd.read()
    # filenames can have ( and ) in them, dammit
    i = s.find('(')
    j = s.rfind(')')
    name = s[i+1:j]
    return s[:i].split() + [name] + s[j+1:].split()

def starttime(pid):
    """starttime(pid) -> float

    Arguments:
        pid (int): PID of the process.

    Returns:
        The time (in seconds) the process started after system boot

    Example:
        >>> starttime(os.getppid()) < starttime(os.getpid())
        True
    """
    return psutil.Process(pid).create_time() - psutil.boot_time()

def status(pid):
    """status(pid) -> dict

    Get the status of a process.

    Arguments:
        pid (int): PID of the process.

    Returns:
        The contents of ``/proc/<pid>/status`` as a dictionary.
    """
    out = {}
    try:
        with open('/proc/%d/status' % pid) as fd:
            for line in fd:
                if ':' not in line:
                    continue
                i = line.index(':')
                key = line[:i]
                val = line[i + 2:-1] # initial :\t and trailing \n
                out[key] = val
    except OSError as e:
        if e.errno == errno.ENOENT:
            raise ValueError('No process with PID %d' % pid)
        else:
            raise
    return out

def tracer(pid):
    """tracer(pid) -> int

    Arguments:
        pid (int): PID of the process.

    Returns:
        PID of the process tracing `pid`, or None if no `pid` is not being traced.

    Example:
        >>> tracer(os.getpid()) is None
        True
    """
    tpid = int(status(pid)['TracerPid'])
    return tpid if tpid > 0 else None

def state(pid):
    """state(pid) -> str

    Arguments:
        pid (int): PID of the process.

    Returns:
        State of the process as listed in ``/proc/<pid>/status``.  See `proc(5)` for details.

    Example:
        >>> state(os.getpid())
        'R (running)'
    """
    return status(pid)['State']

def wait_for_debugger(pid, debugger_pid=None):
    """wait_for_debugger(pid, debugger_pid=None) -> None

    Sleeps until the process with PID `pid` is being traced.
    If debugger_pid is set and debugger exits, raises an error.

    Arguments:
        pid (int): PID of the process.

    Returns:
        None
    """
    t = Timeout()
    with t.countdown(timeout=15):
        with log.waitfor('Waiting for debugger') as l:
            if debugger_pid:
                debugger = psutil.Process(debugger_pid)
                while t.timeout and tracer(pid) is None:
                    try:
                        debugger.wait(0.01)
                    except psutil.TimeoutExpired:
                        pass
                    else:
                        l.failure("debugger exited! (maybe check /proc/sys/kernel/yama/ptrace_scope)")
            else:
                while t.timeout and tracer(pid) is None:
                    time.sleep(0.01)

        if tracer(pid):
            l.success()
        else:
            l.failure('Debugger did not attach to pid %d within 15 seconds', pid)
