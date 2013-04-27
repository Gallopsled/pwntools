import pwn, subprocess, os, time

def pidof(prog):
    if   isinstance(prog, pwn.remote):
        host, port = prog.sock.getpeername()
        local = ['127.0.0.1', '0.0.0.0', '::']
        netstat = subprocess.check_output(['netstat', '-nlptw'],
                                          stderr=subprocess.PIPE)
        for line in netstat.split('\n'):
            if not line.startswith('tcp'):
                continue
            fields = line.split()
            lhost, lport = fields[3].rsplit(':', 1)
            lport = int(lport)
            try:
                pid, name = fields[-1].split('/', 1)
            except:
                continue
            if lport <> port:
                continue
            if lhost == host or (lhost in local and host in local):
                return int(pid)
        pwn.die('Could not find remote process (%s:%d) on this machine' % (host, port))
    elif isinstance(prog, pwn.process):
        return prog.proc.pid
    else:
        return proc_pid_by_name(prog)

def all_pids():
    pids = []
    for pid in os.listdir('/proc'):
        if not pid.isdigit():
            continue
        pid = int(pid)
        if pid < 1000:
            continue
        pids.append(pid)
    return pids

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
