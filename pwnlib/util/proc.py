import os, time, socket, re, struct, errno
from .. import tubes

def pidof(target):
    """pidof(target) -> int list

    Get PID(s) of `target`.  The returned PID(s) depends on the type of `target`:

     - :class:`str`: PIDs of all processing mathing `target`.

     - :class:`pwnlib.tubes.process.process`: singleton list of the PID of `target`.

     - :class:`pwnlib.tubes.sock.sock`: singleton list of the PID at the remote end of `target` if it is running on the host.  Otherwise an empty list.

    Args:
      target(object):  The target whoose PID(s) to find.

    Returns:
      A list of found PIDs.
"""
    if   isinstance(target, tubes.sock.sock):
        def toaddr(sockaddr, family):
            host = sockaddr[0]
            port = sockaddr[1]
            host = socket.inet_pton(family, host)
            if   family == socket.AF_INET:
                host = '%08X' % struct.unpack('<I', host)
            elif family == socket.AF_INET6:
                host = '%08X%08X%08X%08X' % struct.unpack('<IIII', host)
            return '%s:%04X' % (host, port)

        sock = toaddr(target.sock.getsockname(), target.sock.family)
        peer = toaddr(target.sock.getpeername(), target.sock.family)

        # find inode of 'local addr -> remote addr' socket
        inode = None
        for f in ['tcp', 'tcp6']:
            with open('/proc/net/%s' % f) as fd:
                # skip the first line with the column names
                fd.readline()
                for line in fd:
                    line = line.split()
                    loc = line[1]
                    rem = line[2]
                    st = int(line[3], 16)
                    if st != 1: # TCP_ESTABLISHED, see include/net/tcp_states.h
                        continue
                    if loc == peer and rem == sock:
                        inode = int(line[9])
                        break
            if inode:
                break
        if not inode:
            return []

        # find the process who owns this socket
        pid = pid_by_inode(inode)
        return [pid] if pid else None

    elif isinstance(target, tubes.process.process):
        return [target.proc.pid]

    else:
        return pid_by_name(target)

def pid_by_inode(inode):
    """pid_by_inode(inode) -> int or None

    Find the process who owns a given inode

    Args:
      inode (int): The inode to look for.

    Returns:
      The PID of the process who owns `inode`, or :const:`None` if it wasn't
      found.
"""
    inode = str(inode)
    for pid in all_pids():
        try:
            for fd in os.listdir('/proc/%d/fd' % pid):
                try:
                    fd = os.readlink('/proc/%d/fd/%s' % (pid, fd))
                except OSError:
                    continue
                m = re.match(r'socket:\[(\d+)\]', fd)
                if m and m.group(1) == inode:
                    return pid
        except OSError:
            pass

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
        if e.errno == errno.ENOENT:
            raise ValueError('No process with PID %d' % pid)
        else:
            raise
    return out

def pid_by_name(name):
    """pid_by_name(name) -> int list

    Args:
      name (str): Name of program.

    Returns:
      List of PIDs matching `name` sorted by lifetime, youngest to oldest.

    Example:
      >>> pid_by_name('init')
      [1]
"""
    return sorted([pid for pid in all_pids() if status(pid)['Name'] == name],
                  key = starttime, reverse = True)

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

def cwd(pid):
    """cwd(pid) -> str

    Args:
      pid (int): PID of the process.

    Returns:
      The path of the process's current working directory. I.e. what
      ``/proc/<pid>/cwd`` points to.
"""
    return os.readlink('/proc/%d/cwd' % pid)

def cmdline(pid):
    """cmdline(pid) -> str list

    Args:
      pid (int): PID of the process.

    Returns:
      A list of the fields in ``/proc/<pid>/cmdline``.
"""
    with open('/proc/%d/cmdline' % pid, 'r') as fd:
        return fd.read().rstrip('\x00').split('\x00')

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
