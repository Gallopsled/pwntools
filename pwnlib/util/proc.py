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


class MemoryMapFlags:
    """Object with the information of the flags field of maps described in /proc/<pid>/maps

        Arguments:
            readable(bool): True if map is readable
            writable(bool): True if map is writable
            executable(bool): True if map can be executed
            private(bool): True if map is not shared, therefore private

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
        """True if map is shared

        Examples:
            >>> m = MemoryMapFlags.from_str('rw-p')
            >>> m.shared
            False

        Returns:
            bool
        """
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


class MemoryMap:
    """Object with the information of the memory maps described in /proc/<pid>/maps

        Attributes:
            start_address(int): The starting address of the map
            end_address(int): The ending address of the map
            flags(MemoryMapFlags): The flags (read, write, exec, private, shared) of the map
            offset(int): Offset of file mapped. 0 if no file
            device_major(int): Device major version. 0 if no file
            device_minor(int): Device minor version. 0 if no file
            inode(int): Inode of the mapped file. 0 if no file
            path(str): Path of the mapped file. Empty string if no file

        Example:

            >>> m = MemoryMap.from_str("55db09b78000-55db09b81000 rw-p 00114000 fe:01 9832010                    /usr/bins/bash")
            >>> hex(m.start_address)
            '0x55db09b78000'
            >>> hex(m.end_address)
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
            '/usr/bins/bash'
            >>> str(m)
            '55db09b78000-55db09b81000 rw-p 00114000 fe:01 9832010\\t\\t/usr/bins/bash'
    """

    def __init__(self, start_address, end_address, flags, offset, device_major, device_minor, inode, path):
        self.start_address = start_address
        self.end_address = end_address
        self.flags = flags
        self.offset = offset
        self.device_major = device_major
        self.device_minor = device_minor
        self.inode = inode
        self.path = path

    @property
    def address(self):
        """Alias of start_address

        Examples:
            >>> m = MemoryMap.from_str("55db09b78000-55db09b81000 rw-p 00114000 fe:01 9832010                    /usr/bins/bash")
            >>> hex(m.start_address)
            '0x55db09b78000'
            >>> hex(m.address)
            '0x55db09b78000'

        Returns:
            int
        """
        return self.start_address

    @property
    def size(self):
        """The size of the map

        Examples:
            >>> m = MemoryMap.from_str("55db09b78000-55db09b81000 rw-p 00114000 fe:01 9832010                    /usr/bins/bash")
            >>> hex(m.size)
            '0x9000'

        Returns:
            int
        """
        return self.end_address - self.start_address

    @property
    def readable(self):
        """Shorcut for flags.readable

        Examples:
            >>> m = MemoryMap.from_str("55db09b78000-55db09b81000 rw-p 00114000 fe:01 9832010                    /usr/bins/bash")
            >>> m.flags.readable
            True
            >>> m.readable
            True

        Returns:
            bool
        """
        return self.flags.readable

    @property
    def writable(self):
        """Shorcut for flags.writable

        Examples:
            >>> m = MemoryMap.from_str("55db09b78000-55db09b81000 rw-p 00114000 fe:01 9832010                    /usr/bins/bash")
            >>> m.flags.writable
            True
            >>> m.writable
            True

        Returns:
            bool
        """
        return self.flags.writable

    @property
    def executable(self):
        """Shorcut for flags.executable

        Examples:
            >>> m = MemoryMap.from_str("55db09b78000-55db09b81000 rw-p 00114000 fe:01 9832010                    /usr/bins/bash")
            >>> m.flags.executable
            False
            >>> m.executable
            False

        Returns:
            bool
        """
        return self.flags.executable

    @property
    def private(self):
        """Shorcut for flags.private

        Examples:
            >>> m = MemoryMap.from_str("55db09b78000-55db09b81000 rw-p 00114000 fe:01 9832010                    /usr/bins/bash")
            >>> m.flags.private
            True
            >>> m.private
            True

        Returns:
            bool
        """
        return self.flags.private

    @property
    def shared(self):
        """Shorcut for flags.shared

        Examples:
            >>> m = MemoryMap.from_str("55db09b78000-55db09b81000 rw-p 00114000 fe:01 9832010                    /usr/bins/bash")
            >>> m.flags.shared
            False
            >>> m.shared
            False

        Returns:
            bool
        """
        return self.flags.shared

    def is_in_range(self, address):
        """Indicates if the specified addr is in the range of the map

        Arguments:
            address (int): Memory address

        Returns:
            bool: True if addr is in the map memory range

        Example:
            >>> m = MemoryMap.from_str("55db09b78000-55db09b81000 rw-p 00114000 fe:01 9832010                    /usr/bins/bash")
            >>> m.is_in_range(0x55db09b78000)
            True
            >>> m.is_in_range(0x55db09b81000)
            False
            >>> m.is_in_range(0x55db09b78200)
            True
        """
        return self.start_address <= address < self.end_address

    @classmethod
    def from_str(cls, map_str):
        """Retrieves a memory map from a string describing it, such as a line
        of the file /proc/<pid>/maps.

        Args:
            map_str: String which describes a map

        Returns:
            MemoryMap

        Example:
            >>> m = MemoryMap.from_str("55db09b78000-55db09b81000 rw-p 00114000 fe:01 9832010                    /usr/bins/bash")
            >>> str(m)
            '55db09b78000-55db09b81000 rw-p 00114000 fe:01 9832010\\t\\t/usr/bins/bash'
        """
        parts = map_str.split()

        start_address, end_address = parts[0].split("-")
        start_address = int(start_address, 16)
        end_address = int(end_address, 16)

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

        return cls(start_address, end_address, flags, offset, device_major, device_minor, inode, path)

    def __str__(self):
        map_str = ""
        map_str += "%x-%x" % (self.start_address, self.end_address)
        map_str += " %s" % self.flags
        map_str += " %08x" % self.offset
        map_str += " %02x:%02x" % (self.device_major, self.device_minor)
        map_str += " %d" % self.inode

        if self.path:
            map_str += "\t\t%s" % self.path

        return map_str


class MemoryMaps:
    """List of the memory maps described in /proc/<pid>/maps

        Arguments:
            maps(list of MemoryMap): The memory maps

        Example:

            >>> maps = MemoryMaps.from_str(\"""561ce1d6f000-561ce1d70000 r--p 00000000 fe:01 3676814                    /home/zrt/test
            ... 561ce1d70000-561ce1d71000 r-xp 00001000 fe:01 3676814                    /home/zrt/test
            ... 561ce1d71000-561ce1d72000 r--p 00002000 fe:01 3676814                    /home/zrt/test
            ... 561ce1d72000-561ce1d73000 r--p 00002000 fe:01 3676814                    /home/zrt/test
            ... 561ce1d73000-561ce1d74000 rw-p 00003000 fe:01 3676814                    /home/zrt/test
            ... 561ce2895000-561ce28b6000 rw-p 00000000 00:00 0                          [heap]
            ... 7f6e59ff0000-7f6e5a012000 r--p 00000000 fe:01 9831037                    /usr/lib/x86_64-linux-gnu/libc-2.28.so
            ... 7f6e5a012000-7f6e5a15a000 r-xp 00022000 fe:01 9831037                    /usr/lib/x86_64-linux-gnu/libc-2.28.so
            ... 7f6e5a15a000-7f6e5a1a6000 r--p 0016a000 fe:01 9831037                    /usr/lib/x86_64-linux-gnu/libc-2.28.so
            ... 7f6e5a1a6000-7f6e5a1a7000 ---p 001b6000 fe:01 9831037                    /usr/lib/x86_64-linux-gnu/libc-2.28.so
            ... 7f6e5a1a7000-7f6e5a1ab000 r--p 001b6000 fe:01 9831037                    /usr/lib/x86_64-linux-gnu/libc-2.28.so
            ... 7f6e5a1ab000-7f6e5a1ad000 rw-p 001ba000 fe:01 9831037                    /usr/lib/x86_64-linux-gnu/libc-2.28.so
            ... 7f6e5a1ad000-7f6e5a1b3000 rw-p 00000000 00:00 0
            ... 7f6e5a1cd000-7f6e5a1ce000 r--p 00000000 fe:01 9830423                    /usr/lib/x86_64-linux-gnu/ld-2.28.so
            ... 7f6e5a1ce000-7f6e5a1ec000 r-xp 00001000 fe:01 9830423                    /usr/lib/x86_64-linux-gnu/ld-2.28.so
            ... 7f6e5a1ec000-7f6e5a1f4000 r--p 0001f000 fe:01 9830423                    /usr/lib/x86_64-linux-gnu/ld-2.28.so
            ... 7f6e5a1f4000-7f6e5a1f5000 r--p 00026000 fe:01 9830423                    /usr/lib/x86_64-linux-gnu/ld-2.28.so
            ... 7f6e5a1f5000-7f6e5a1f6000 rw-p 00027000 fe:01 9830423                    /usr/lib/x86_64-linux-gnu/ld-2.28.so
            ... 7f6e5a1f6000-7f6e5a1f7000 rw-p 00000000 00:00 0
            ... 7ffd9bab9000-7ffd9bada000 rw-p 00000000 00:00 0                          [stack]
            ... 7ffd9bb45000-7ffd9bb48000 r--p 00000000 00:00 0                          [vvar]
            ... 7ffd9bb48000-7ffd9bb4a000 r-xp 00000000 00:00 0                          [vdso]
            ... \""")
            >>> str(maps.heap)
            '561ce2895000-561ce28b6000 rw-p 00000000 00:00 0\\t\\t[heap]'
            >>> str(maps.stack)
            '7ffd9bab9000-7ffd9bada000 rw-p 00000000 00:00 0\\t\\t[stack]'
            >>> len(maps)
            22
    """

    def __init__(self, maps):
        self.maps = maps

    @classmethod
    def from_process(cls, pid):
        """Creates a new instance of MemoryMaps from a process.

        Args:
            pid: PID of the target process.

        Returns:
            MemoryMaps

        Examples:
            >>> import os
            >>> maps = MemoryMaps.from_process(os.getpid())
            >>> str(maps[0]) #doctest: +SKIP
            '400000-421000 r--p 00000000 fe:01 9836223\t\t/usr/bin/python3.7'
            >>> str(maps[len(maps) - 1]) #doctest: +SKIP
            '7fff8d16e000-7fff8d170000 r-xp 00000000 00:00 0\t\t[vdso]'
        """
        with open('/proc/%s/maps' % pid) as fmap:
            maps_raw = fmap.read()

        return cls.from_str(maps_raw)

    @classmethod
    def from_str(cls, maps_string):
        """Creates a new instance of MemoryMaps from a string with the maps
        described, usually the content of /proc/<pid>/maps.

        Args:
            maps_string: The description of the maps in string format. Usually
                the content of /proc/<pid>/maps.

        Returns:
            MemoryMaps

        Examples:
            >>> maps = MemoryMaps.from_str(\"""561ce1d6f000-561ce1d70000 r--p 00000000 fe:01 3676814                    /home/zrt/test
            ... 561ce1d70000-561ce1d71000 r-xp 00001000 fe:01 3676814                    /home/zrt/test
            ... 561ce1d71000-561ce1d72000 r--p 00002000 fe:01 3676814                    /home/zrt/test
            ... 561ce1d72000-561ce1d73000 r--p 00002000 fe:01 3676814                    /home/zrt/test
            ... 561ce1d73000-561ce1d74000 rw-p 00003000 fe:01 3676814                    /home/zrt/test
            ... 561ce2895000-561ce28b6000 rw-p 00000000 00:00 0                          [heap]
            ... 7f6e59ff0000-7f6e5a012000 r--p 00000000 fe:01 9831037                    /usr/lib/x86_64-linux-gnu/libc-2.28.so
            ... 7f6e5a012000-7f6e5a15a000 r-xp 00022000 fe:01 9831037                    /usr/lib/x86_64-linux-gnu/libc-2.28.so
            ... 7f6e5a15a000-7f6e5a1a6000 r--p 0016a000 fe:01 9831037                    /usr/lib/x86_64-linux-gnu/libc-2.28.so
            ... 7f6e5a1a6000-7f6e5a1a7000 ---p 001b6000 fe:01 9831037                    /usr/lib/x86_64-linux-gnu/libc-2.28.so
            ... 7f6e5a1a7000-7f6e5a1ab000 r--p 001b6000 fe:01 9831037                    /usr/lib/x86_64-linux-gnu/libc-2.28.so
            ... 7f6e5a1ab000-7f6e5a1ad000 rw-p 001ba000 fe:01 9831037                    /usr/lib/x86_64-linux-gnu/libc-2.28.so
            ... 7f6e5a1ad000-7f6e5a1b3000 rw-p 00000000 00:00 0
            ... 7f6e5a1cd000-7f6e5a1ce000 r--p 00000000 fe:01 9830423                    /usr/lib/x86_64-linux-gnu/ld-2.28.so
            ... 7f6e5a1ce000-7f6e5a1ec000 r-xp 00001000 fe:01 9830423                    /usr/lib/x86_64-linux-gnu/ld-2.28.so
            ... 7f6e5a1ec000-7f6e5a1f4000 r--p 0001f000 fe:01 9830423                    /usr/lib/x86_64-linux-gnu/ld-2.28.so
            ... 7f6e5a1f4000-7f6e5a1f5000 r--p 00026000 fe:01 9830423                    /usr/lib/x86_64-linux-gnu/ld-2.28.so
            ... 7f6e5a1f5000-7f6e5a1f6000 rw-p 00027000 fe:01 9830423                    /usr/lib/x86_64-linux-gnu/ld-2.28.so
            ... 7f6e5a1f6000-7f6e5a1f7000 rw-p 00000000 00:00 0
            ... 7ffd9bab9000-7ffd9bada000 rw-p 00000000 00:00 0                          [stack]
            ... 7ffd9bb45000-7ffd9bb48000 r--p 00000000 00:00 0                          [vvar]
            ... 7ffd9bb48000-7ffd9bb4a000 r-xp 00000000 00:00 0                          [vdso]
            ... \""")
            >>> str(maps[0])
            '561ce1d6f000-561ce1d70000 r--p 00000000 fe:01 3676814\\t\\t/home/zrt/test'
            >>> str(maps[len(maps) - 1])
            '7ffd9bb48000-7ffd9bb4a000 r-xp 00000000 00:00 0\\t\\t[vdso]'

        """
        maps = [MemoryMap.from_str(line) for line in maps_string.splitlines()]
        return cls(maps)

    def map_with_address(self, address):
        """Returns the map which contains the given address

            Arguments:
                address (int): Memory addr

            Raises:
                IndexError: When given address is not in the range of any
                memory map

            Returns:
                MemoryMap

            >>> maps = MemoryMaps.from_str(\"""561ce1d6f000-561ce1d70000 r--p 00000000 fe:01 3676814                    /tmp/test
            ... 561ce1d70000-561ce1d71000 r-xp 00001000 fe:01 3676814                    /home/zrt/test
            ... 561ce1d71000-561ce1d72000 r--p 00002000 fe:01 3676814                    /home/zrt/test
            ... 561ce1d72000-561ce1d73000 r--p 00002000 fe:01 3676814                    /home/zrt/test
            ... 561ce1d73000-561ce1d74000 rw-p 00003000 fe:01 3676814                    /home/zrt/test
            ... 561ce2895000-561ce28b6000 rw-p 00000000 00:00 0                          [heap]
            ... 7f6e59ff0000-7f6e5a012000 r--p 00000000 fe:01 9831037                    /usr/lib/x86_64-linux-gnu/libc-2.28.so
            ... 7f6e5a012000-7f6e5a15a000 r-xp 00022000 fe:01 9831037                    /usr/lib/x86_64-linux-gnu/libc-2.28.so
            ... 7f6e5a15a000-7f6e5a1a6000 r--p 0016a000 fe:01 9831037                    /usr/lib/x86_64-linux-gnu/libc-2.28.so
            ... 7f6e5a1a6000-7f6e5a1a7000 ---p 001b6000 fe:01 9831037                    /usr/lib/x86_64-linux-gnu/libc-2.28.so
            ... 7f6e5a1a7000-7f6e5a1ab000 r--p 001b6000 fe:01 9831037                    /usr/lib/x86_64-linux-gnu/libc-2.28.so
            ... 7f6e5a1ab000-7f6e5a1ad000 rw-p 001ba000 fe:01 9831037                    /usr/lib/x86_64-linux-gnu/libc-2.28.so
            ... 7f6e5a1ad000-7f6e5a1b3000 rw-p 00000000 00:00 0
            ... 7f6e5a1cd000-7f6e5a1ce000 r--p 00000000 fe:01 9830423                    /usr/lib/x86_64-linux-gnu/ld-2.28.so
            ... 7f6e5a1ce000-7f6e5a1ec000 r-xp 00001000 fe:01 9830423                    /usr/lib/x86_64-linux-gnu/ld-2.28.so
            ... 7f6e5a1ec000-7f6e5a1f4000 r--p 0001f000 fe:01 9830423                    /usr/lib/x86_64-linux-gnu/ld-2.28.so
            ... 7f6e5a1f4000-7f6e5a1f5000 r--p 00026000 fe:01 9830423                    /usr/lib/x86_64-linux-gnu/ld-2.28.so
            ... 7f6e5a1f5000-7f6e5a1f6000 rw-p 00027000 fe:01 9830423                    /usr/lib/x86_64-linux-gnu/ld-2.28.so
            ... 7f6e5a1f6000-7f6e5a1f7000 rw-p 00000000 00:00 0
            ... 7ffd9bab9000-7ffd9bada000 rw-p 00000000 00:00 0                          [stack]
            ... 7ffd9bb45000-7ffd9bb48000 r--p 00000000 00:00 0                          [vvar]
            ... 7ffd9bb48000-7ffd9bb4a000 r-xp 00000000 00:00 0                          [vdso]
            ... \""")
            >>> str(maps.map_with_address(0x7ffd9bb48200))
            '7ffd9bb48000-7ffd9bb4a000 r-xp 00000000 00:00 0\\t\\t[vdso]'
            >>> try:
            ...     maps.map_with_address(0xdeadbeef)
            ... except IndexError as ex:
            ...     print(ex)
            ...
            address out of range

        """
        for map_ in self.maps:
            if map_.is_in_range(address):
                return map_
        raise IndexError("address {:#x} out of range".format(address))

    @property
    def heap(self):
        """Shortcut to retrieve the map named "[heap]"

        Raises:
            KeyError: The map "[heap]" was not found

        Returns:
            MemoryMap

        Examples:
            >>> maps = MemoryMaps.from_str(\"""561ce1d6f000-561ce1d70000 r--p 00000000 fe:01 3676814                    /tmp/test
            ... 561ce1d70000-561ce1d71000 r-xp 00001000 fe:01 3676814                    /home/zrt/test
            ... 561ce1d71000-561ce1d72000 r--p 00002000 fe:01 3676814                    /home/zrt/test
            ... 561ce1d72000-561ce1d73000 r--p 00002000 fe:01 3676814                    /home/zrt/test
            ... 561ce1d73000-561ce1d74000 rw-p 00003000 fe:01 3676814                    /home/zrt/test
            ... 561ce2895000-561ce28b6000 rw-p 00000000 00:00 0                          [heap]
            ... 7f6e59ff0000-7f6e5a012000 r--p 00000000 fe:01 9831037                    /usr/lib/x86_64-linux-gnu/libc-2.28.so
            ... 7f6e5a012000-7f6e5a15a000 r-xp 00022000 fe:01 9831037                    /usr/lib/x86_64-linux-gnu/libc-2.28.so
            ... 7f6e5a15a000-7f6e5a1a6000 r--p 0016a000 fe:01 9831037                    /usr/lib/x86_64-linux-gnu/libc-2.28.so
            ... 7f6e5a1a6000-7f6e5a1a7000 ---p 001b6000 fe:01 9831037                    /usr/lib/x86_64-linux-gnu/libc-2.28.so
            ... 7f6e5a1a7000-7f6e5a1ab000 r--p 001b6000 fe:01 9831037                    /usr/lib/x86_64-linux-gnu/libc-2.28.so
            ... 7f6e5a1ab000-7f6e5a1ad000 rw-p 001ba000 fe:01 9831037                    /usr/lib/x86_64-linux-gnu/libc-2.28.so
            ... 7f6e5a1ad000-7f6e5a1b3000 rw-p 00000000 00:00 0
            ... 7f6e5a1cd000-7f6e5a1ce000 r--p 00000000 fe:01 9830423                    /usr/lib/x86_64-linux-gnu/ld-2.28.so
            ... 7f6e5a1ce000-7f6e5a1ec000 r-xp 00001000 fe:01 9830423                    /usr/lib/x86_64-linux-gnu/ld-2.28.so
            ... 7f6e5a1ec000-7f6e5a1f4000 r--p 0001f000 fe:01 9830423                    /usr/lib/x86_64-linux-gnu/ld-2.28.so
            ... 7f6e5a1f4000-7f6e5a1f5000 r--p 00026000 fe:01 9830423                    /usr/lib/x86_64-linux-gnu/ld-2.28.so
            ... 7f6e5a1f5000-7f6e5a1f6000 rw-p 00027000 fe:01 9830423                    /usr/lib/x86_64-linux-gnu/ld-2.28.so
            ... 7f6e5a1f6000-7f6e5a1f7000 rw-p 00000000 00:00 0
            ... 7ffd9bab9000-7ffd9bada000 rw-p 00000000 00:00 0                          [stack]
            ... 7ffd9bb45000-7ffd9bb48000 r--p 00000000 00:00 0                          [vvar]
            ... 7ffd9bb48000-7ffd9bb4a000 r-xp 00000000 00:00 0                          [vdso]
            ... \""")
            >>> str(maps.heap)
            '561ce2895000-561ce28b6000 rw-p 00000000 00:00 0\\t\\t[heap]'

        """
        return self._lookup_map("[heap]")

    @property
    def stack(self):
        """Shortcut to retrieve the map named "[stack]"

        Raises:
            KeyError: The map "[stack]" was not found

        Returns:
            MemoryMap

        Examples:
            >>> maps = MemoryMaps.from_str(\"""561ce1d6f000-561ce1d70000 r--p 00000000 fe:01 3676814                    /tmp/test
            ... 561ce1d70000-561ce1d71000 r-xp 00001000 fe:01 3676814                    /home/zrt/test
            ... 561ce1d71000-561ce1d72000 r--p 00002000 fe:01 3676814                    /home/zrt/test
            ... 561ce1d72000-561ce1d73000 r--p 00002000 fe:01 3676814                    /home/zrt/test
            ... 561ce1d73000-561ce1d74000 rw-p 00003000 fe:01 3676814                    /home/zrt/test
            ... 561ce2895000-561ce28b6000 rw-p 00000000 00:00 0                          [heap]
            ... 7f6e59ff0000-7f6e5a012000 r--p 00000000 fe:01 9831037                    /usr/lib/x86_64-linux-gnu/libc-2.28.so
            ... 7f6e5a012000-7f6e5a15a000 r-xp 00022000 fe:01 9831037                    /usr/lib/x86_64-linux-gnu/libc-2.28.so
            ... 7f6e5a15a000-7f6e5a1a6000 r--p 0016a000 fe:01 9831037                    /usr/lib/x86_64-linux-gnu/libc-2.28.so
            ... 7f6e5a1a6000-7f6e5a1a7000 ---p 001b6000 fe:01 9831037                    /usr/lib/x86_64-linux-gnu/libc-2.28.so
            ... 7f6e5a1a7000-7f6e5a1ab000 r--p 001b6000 fe:01 9831037                    /usr/lib/x86_64-linux-gnu/libc-2.28.so
            ... 7f6e5a1ab000-7f6e5a1ad000 rw-p 001ba000 fe:01 9831037                    /usr/lib/x86_64-linux-gnu/libc-2.28.so
            ... 7f6e5a1ad000-7f6e5a1b3000 rw-p 00000000 00:00 0
            ... 7f6e5a1cd000-7f6e5a1ce000 r--p 00000000 fe:01 9830423                    /usr/lib/x86_64-linux-gnu/ld-2.28.so
            ... 7f6e5a1ce000-7f6e5a1ec000 r-xp 00001000 fe:01 9830423                    /usr/lib/x86_64-linux-gnu/ld-2.28.so
            ... 7f6e5a1ec000-7f6e5a1f4000 r--p 0001f000 fe:01 9830423                    /usr/lib/x86_64-linux-gnu/ld-2.28.so
            ... 7f6e5a1f4000-7f6e5a1f5000 r--p 00026000 fe:01 9830423                    /usr/lib/x86_64-linux-gnu/ld-2.28.so
            ... 7f6e5a1f5000-7f6e5a1f6000 rw-p 00027000 fe:01 9830423                    /usr/lib/x86_64-linux-gnu/ld-2.28.so
            ... 7f6e5a1f6000-7f6e5a1f7000 rw-p 00000000 00:00 0
            ... 7ffd9bab9000-7ffd9bada000 rw-p 00000000 00:00 0                          [stack]
            ... 7ffd9bb45000-7ffd9bb48000 r--p 00000000 00:00 0                          [vvar]
            ... 7ffd9bb48000-7ffd9bb4a000 r-xp 00000000 00:00 0                          [vdso]
            ... \""")
            >>> str(maps.stack)
            '7ffd9bab9000-7ffd9bada000 rw-p 00000000 00:00 0\\t\\t[stack]'

        """
        return self._lookup_map("[stack]")

    def _lookup_map(self, map_path):
        """Retrieves the first map with the name or file path given

        Args:
            map_path: The path of file or name of the map

        Raises:
            KeyError: The map was not found

        Returns:
            MemoryMap
        """
        for map_ in self.maps:
            if map_.path == map_path:
                return map_
        raise KeyError(map_path)

    def __str__(self):
        return "\n".join([str(map_) for map_ in self.maps])

    def __len__(self):
        return len(self.maps)

    def __getitem__(self, index):
        return self.maps[index]

    def __iter__(self):
        return iter(self.maps)
