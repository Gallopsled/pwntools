from __future__ import absolute_import

import errno
import socket
import time

import psutil

from pwnlib import tubes
from pwnlib.log import getLogger

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
    """
    if isinstance(target, tubes.ssh.ssh_channel):
        return [target.pid]

    elif isinstance(target, tubes.sock.sock):
         local  = target.sock.getsockname()
         remote = target.sock.getpeername()

         def match(c):
             return (c.raddr, c.laddr, c.status) == (local, remote, 'ESTABLISHED')

         return [c.pid for c in psutil.net_connections() if match(c)]

    elif isinstance(target, tuple):
        host, port = target

        host = socket.gethostbyname(host)

        def match(c):
            return c.raddr == (host, port)

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

    processes = sorted(processes, key=lambda p: p.create_time())

    return list(reversed([p.pid for p in processes]))

def name(pid):
    """name(pid) -> str

    Arguments:
        pid (int): PID of the process.

    Returns:
        Name of process as listed in ``/proc/<pid>/status``.

    Example:
        >>> pid = pidof('init')[0]
        >>> name(pid) == 'init'
        True
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
    """
    return psutil.Process(pid).exe()

def cwd(pid):
    """cwd(pid) -> str

    Arguments:
        pid (int): PID of the process.

    Returns:
        The path of the process's current working directory. I.e. what
        ``/proc/<pid>/cwd`` points to.
    """
    return psutil.Process(pid).cwd()

def cmdline(pid):
    """cmdline(pid) -> str list

    Arguments:
        pid (int): PID of the process.

    Returns:
        A list of the fields in ``/proc/<pid>/cmdline``.
    """
    return psutil.Process(pid).cmdline()

def stat(pid):
    """stat(pid) -> str list

    Arguments:
        pid (int): PID of the process.

    Returns:
        A list of the values in ``/proc/<pid>/stat``, with the exception that ``(`` and ``)`` has been removed from around the process name.
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

def wait_for_debugger(pid):
    """wait_for_debugger(pid) -> None

    Sleeps until the process with PID `pid` is being traced.

    Arguments:
        pid (int): PID of the process.

    Returns:
        None
    """
    with log.waitfor('Waiting for debugger') as l:
        while tracer(pid) is None:
            time.sleep(0.01)
        l.success()
