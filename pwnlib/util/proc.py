from __future__ import absolute_import
from __future__ import division

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

    return reversed([p.pid for p in processes])

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


class MemoryMap:
    """Object with the information of the memory maps described in /proc/<pid>/maps

        Arguments:
            start_addr(int): The starting address of the map
            end_addr(int): The ending address of the map
            flags(MemoryMapFlags): The flags (read, write, exec, private, shared) of the map
            offset(int): Offset of file mapped. 0 if no file
            device_major(int): Device major version. 0 if no file
            device_minor(int): Device minor version. 0 if no file
            inode(int): Inode of the mapped file. 0 if no file
            path(str): Path of the mapped file. Empty string if no file
        
        Example:

            >>> m = MemoryMap.from_str("55db09b78000-55db09b81000 rw-p 00114000 fe:01 9832010                    /usr/bin/bash")
            >>> hex(m.start_addr)
            '0x55db09b78000'
            >>> hex(m.end_addr)
            '0x55db09b81000'
            >>> m.readable
            True
            >>> m.writable
            True
            >>> m.executable
            False
            >>> m.private
            True
            >>> m.shared
            False
            >>> hex(m.offset)
            '0x114000'
            >>> hex(m.device_major)
            '0xfe'
            >>> hex(m.device_minor)
            '0x1'
            >>> m.inode
            9832010
            >>> m.path
            '/usr/bin/bash'
            >>> str(m)
            '55db09b78000-55db09b81000 rw-p 00114000 fe:01 9832010\\t\\t/usr/bin/bash'
    """

    def __init__(self, start_addr, end_addr, flags, offset, device_major, device_minor, inode, path):
        self.start_addr = start_addr
        self.end_addr = end_addr
        self.flags = flags
        self.offset = offset
        self.device_major = device_major
        self.device_minor = device_minor
        self.inode = inode
        self.path = path
    
    @property
    def size(self):
        """The size of the map"""
        return self.end_addr - self.start_addr
    
    @property
    def readable(self):
        return self.flags.readable
    
    @property
    def writable(self):
        return self.flags.writable
    
    @property
    def executable(self):
        return self.flags.executable

    @property
    def private(self):
        return self.flags.private

    @property
    def shared(self):
        return self.flags.shared

    @classmethod
    def from_str(cls, map_str):
        parts = map_str.split()

        start_addr, end_addr = parts[0].split("-")
        start_addr = int(start_addr, 16)
        end_addr = int(end_addr, 16)

        flags = MemoryMapFlags.from_str(parts[1])

        offset = int(parts[2], 16)

        device_major, device_minor = parts[3].split(":")
        device_major = int(device_major, 16)
        device_minor = int(device_minor, 16)

        inode = int(parts[4])

        try:
            path = parts[5]
        except IndexError:
            path = ""

        return cls(start_addr, end_addr, flags, offset, device_major, device_minor, inode, path)

    def __str__(self):
        map_str = ""
        map_str += "%x-%x" % (self.start_addr, self.end_addr)
        map_str += " %s" % self.flags
        map_str += " %08x" % self.offset
        map_str += " %02x:%02x" % (self.device_major, self.device_minor)
        map_str += " %d" % self.inode

        if self.path:
            map_str += "\t\t%s" % self.path

        return map_str

class MemoryMapFlags:
    """Object with the information of the flags field of maps described in /proc/<pid>/maps

        Arguments:
            readable(bool): True if map is readable
            writable(bool): True if map is writable
            executable(bool): True if map can be executed
            private(bool): True if map is not shared
        
        Example:

            >>> m = MemoryMapFlags.from_str('rw-p')
            >>> m.readable
            True
            >>> m.writable
            True
            >>> m.executable
            False
            >>> m.private
            True
            >>> m.shared
            False
            >>> str(m)
            'rw-p'
    """

    def __init__(self, readable, writable, executable, private):
        self.readable = readable
        self.writable = writable
        self.executable = executable
        self.private = private

    @property
    def shared(self):
        return not self.private

    @classmethod
    def from_str(cls, flags_str):
        """Generates a MemoryMapFlags object from a flags string. Example: 'r-xp'

        Arguments:
            flags_str(str): Flag string with the format contained in /proc/pid/maps
        
        Returns:
            MemoryMapFlags: The object representation of the string

         Example:

            >>> str(MemoryMapFlags.from_str('r-xp'))
            'r-xp'
        """
        readable = flags_str[0] == "r"
        writable = flags_str[1] == "w"
        executable = flags_str[2] == "x"
        private = flags_str[3] == "p"
        return cls(readable, writable, executable, private)

    def __str__(self):
        flags_str = ""
        flags_str += "r" if self.readable else "-"
        flags_str += "w" if self.writable else "-"
        flags_str += "x" if self.executable else "-"
        flags_str += "p" if self.private else "s"
        return flags_str
