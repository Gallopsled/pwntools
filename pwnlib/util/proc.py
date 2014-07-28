import os, time, socket, re, struct
from . import packing
from .. import tubes

def pidof(target):
    """pidof(target) -> int list

    Get PID(s) of `target`.  The returned PID(s) depends on the type of `target`:

     - :class:`str`: PIDs of all processing mathing `target`.

     - :class:`pwnlib.tubes.process.process`: singleton list of the PID of `target`.

     - :class:`pwnlib.tubes.remote.remote`: singleton list of the PID at the remote end of `target` if it is running on the host.  Otherwise an empty list.

    *WARNING*: At this time only IPv4 is supported.

    Args:
      target(object):  The target whoose PID(s) to find.

    Returns:
      A list of found PIDs.
"""
    if   isinstance(target, tubes.remote.remote):
        # XXX: handle IPv6
        def toaddr((host, port)):
            return '%08X:%04X' % \
                (struct.unpack('<I', socket.inet_aton(host))[0], port)
        sock = toaddr(target.sock.getsockname())
        peer = toaddr(target.sock.getpeername())

        # find inode of 'local addr -> remote addr' socket
        inode = None
        with open('/proc/net/tcp') as fd:
            for line in fd:
                line = line.split()
                loc = line[1]
                rem = line[2]
                if loc == peer and rem == sock:
                    inode = line[9]
                    break
        if not inode:
            return []

        # find the process who owns this socket
        for pid in all_pids():
            try:
                for fd in os.listdir('/proc/%d/fd' % pid):
                    try:
                        fd = os.readlink('/proc/%d/fd/%s' % (pid, fd))
                    except OSError:
                        continue
                    m = re.match('socket:\[(\d+)\]', fd)
                    if m and m.group(1) == inode:
                        return [pid]
            except OSError:
                pass

        return [pid]

    elif isinstance(target, tubes.process.process):
        return [target.proc.pid]

    else:
        return pid_by_name(target)

def all_pids():
    """all_pids() -> int list

    Args:
      None

    Returns:
      List of the PIDs of all processes on the system
"""
    return [int(pid) for pid in os.listdir('/proc') if pid.isdigit()]

def status(pid):
    """status(pid) -> dict

    Get the status of a process.

    Args:
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
        if e.errno == errno.NOENT:
            raise ValueError('No process with PID %d' % pid)
        else:
            raise
    return out

def pid_by_name(name):
    """pid_by_name(name) -> int list

    Args:
      name (str): Name of program.

    Returns:
      List of PIDs matching `name`.

    Example:
      >>> pid_by_name('init')
      [1]
"""
    return [pid for pid in all_pids() if status(pid)['Name'] == name]

def name(pid):
    """name(pid) -> str

    Args:
      pid (int): PID of the process.

    Returns:
      Name of process as listed in ``/proc/<pid>/status``.

    Example:
      >>> name(1)
      'init'
"""
    return status(pid)['Name']

def parent(pid):
    """parent(pid) -> int

    Args:
      pid (int): PID of the process.

    Returns:
      Parent PID as listed in ``/proc/<pid>/status`` under ``PPid``.
"""
    return int(status(pid)['PPid'])

def children(ppid):
    """children(ppid) -> int list

    Args:
      pid (int): PID of the process.

    Returns:
      List of PIDs of whoose parent process is `pid`.
"""
    return [pid for pid in all_pids() if parent(pid) == ppid]

def ancestors(pid):
    """ancestors(pid) -> int list

    Args:
      pid (int): PID of the process.

    Returns:
      List of PIDs of whoose parent process is `pid` or an ancestor of `pid`.
"""
    pids = []
    while pid != 0:
        pids.append(pid)
        pid = parent(pid)
    return pids

def descendants(pid):
    """descendants(pid) -> dict

    Args:
      pid (int): PID of the process.

    Returns:
      Dictionary mapping the PID of each child of `pid` to it's descendants.
"""
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

def tracer(pid):
    """tracer(pid) -> int

    Args:
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

    Args:
      pid (int): PID of the process.

    Returns:
      State of the process as listed in ``/proc/<pid>/status``.  See `proc(5)` for details.

    Example:
      >>> state(os.getpid())
      'R (running)'
"""
    return status(pid)['State']

def exe(pid):
    """exe(pid) -> str

    Args:
      pid (int): PID of the process.

    Returns:
      The path of the binary of the process. I.e. what ``/proc/<pid>/exe`` points to.
"""
    return os.readlink('/proc/%d/exe' % pid)

def stat(pid):
    """stat(pid) -> str list

    Args:
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

    Args:
      pid (int): PID of the process.

    Returns:
      The time (in seconds) the process started after system boot
"""
    return float(stat(pid)[21]) / os.sysconf(os.sysconf_names['SC_CLK_TCK'])

def wait_for_debugger(pid):
    """wait_for_debugger(pid) -> None

    Sleeps until the process with PID `pid` is being traced.

    Args:
      pid (int): PID of the process.

    Returns:
      None
"""
    while tracer(pid) is None:
        time.sleep(0.01)
