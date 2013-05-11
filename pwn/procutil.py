import pwn, subprocess, os, time, socket, re

def which(name, flags = os.X_OK, find_all = False):
    out = []
    try:
        path = os.environ['PATH']
    except KeyError:
        pwn.die('No PATH environment variable')
    for p in path.split(os.pathsep):
        p = os.path.join(p, name)
        if os.access(p, flags):
            out.append(p)
    if find_all:
        return out
    else:
        return out[0] if out else None

def pidof(prog):
    '''Get PID, depending on type:
    string  : pids of all processes matching name
    process : singleton list of process\'s pid
    remote  : list of remote and local pid (remote pid first, None if remote process
              is not running locally)'''
    if   isinstance(prog, pwn.remote):
        def toaddr((host, port)):
            return '%08X:%04X' % (pwn.u32(socket.inet_aton(host)), port)
        def getpid(loc, rem):
            loc = toaddr(loc)
            rem = toaddr(rem)
            inode = 0
            with open('/proc/net/tcp') as fd:
                for line in fd:
                    line = line.split()
                    if line[1] == loc and line[2] == rem:
                        inode = line[9]
            if inode == 0:
                return []
            for pid in all_pids():
                try:
                    for fd in os.listdir('/proc/%d/fd' % pid):
                        fd = os.readlink('/proc/%d/fd/%s' % (pid, fd))
                        m = re.match('socket:\[(\d+)\]', fd)
                        if m:
                            this_inode = m.group(1)
                            if this_inode == inode:
                                return pid
                except:
                    pass
        sock = prog.sock.getsockname()
        peer = prog.sock.getpeername()
        return [getpid(peer, sock), getpid(sock, peer)]
    elif isinstance(prog, pwn.process):
        return [prog.proc.pid]
    else:
        return proc_pid_by_name(prog)

def all_pids():
    return [int(pid) for pid in os.listdir('/proc') if pid.isdigit()]

def proc_status(pid):
    out = {}
    with open('/proc/%d/status' % pid) as fd:
        for line in fd:
            i = line.index(':')
            key = line[:i]
            val = line[i + 2:-1] # initial :\t and trailing \n
            out[key] = val
    return out

def proc_pid_by_name(name):
    return [pid for pid in all_pids() if proc_name(pid) == name]

def proc_name(pid):
    return proc_status(pid)['Name']

def proc_parent(pid):
    return int(proc_status(pid)['PPid'])

def proc_children(ppid):
    return [pid for pid in all_pids() if proc_parent(pid) == ppid]

def proc_ancestors(pid):
    pids = []
    while pid <> 0:
        pids.append(pid)
        pid = proc_parent(pid)
    return pids

def proc_descendants(ppid):
    # XXX: cracy slow, fix plox
    return {pid : proc_descendants(pid) for pid in proc_children(ppid)}

def proc_tracer(pid):
    tpid = int(proc_status(pid)['TracerPid'])
    return tpid if tpid > 0 else None

def proc_state(pid):
    return proc_status(pid)['State'][0]

def proc_exe(pid):
    return os.readlink('/proc/%d/exe' % pid)

def proc_stat(pid):
    with open('/proc/%d/stat' % pid) as fd:
        s = fd.read()
        # filenames can have ( and ) in them, dammit
        i = s.find('(')
        j = s.rfind(')')
        name = s[i+1:j]
        s = s[:i] + 'x' + s[j+1:]
        xs = s.split()
        xs[1] = name
        return xs

def proc_starttime(pid):
    return int(proc_stat(pid)[21])

def wait_for_debugger(pid):
    while proc_tracer(pid) is None:
        time.sleep(0.01)
