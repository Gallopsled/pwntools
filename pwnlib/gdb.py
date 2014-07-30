import os, socket, struct, tempfile
from . import log
from .util import misc, proc
from . import tubes

def attach(target, execute = None, exe = None, arch = None):
    # if execute is a file object, then read it; we probably need to run some
    # more gdb script anyway
    if execute:
        if isinstance(execute, file):
            fd = execute
            execute = fd.read()
            fd.close()

    # gdb script to run before `execute`
    pre = ''
    if arch:
        pre += 'set architechture %s\n' % arch

    # let's see if we can find a pid to attach to
    pid = None
    if   isinstance(target, (int, long)):
        # target is a pid, easy peasy
        pid = target
    elif isinstance(target, str):
        # pidof picks the youngest process
        pids = proc.pidof(target)
        if not pids:
            log.error('no such process: %s' % target)
        pid = pids[0]
        log.info('attaching you youngest process "%s" (PID = %d)' %
                 (target, pid))
    elif isinstance(target, tubes.remote.remote):
        pids = proc.pidof(target)
        if not pids:
            log.error('could not find remote process (%s:%d) on this machine' %
                      target.sock.getpeername())
        pid = pids[0]
    elif isinstance(target, tubes.process.process):
        pid = proc.pidof(target)[0]
    elif isinstance(target, tuple) and len(target) == 2:
        host, port = target
        pre += 'target remote %s:%d\n' % (host, port)
        def findexe():
            # hm no PID then, but wait! we might not be totally out of luck yet: if
            # the gdbserver is running locally and we know the program who is
            # hosting it (e.g qemu, gdbserver) we can figure out the `exe` from the
            # command line

            # find inode of the listen socket
            inode = None

            # XXX: do a proper check to see if we're hosting the server
            if host not in ('localhost', '127.0.0.1', '0.0.0.0',
                            '::1', 'ip6-localhost', '::'):
                return

            for f in ['tcp', 'tcp6']:
                with open('/proc/net/%s' % f) as fd:
                    # skip the first line with the column names
                    fd.readline()
                    for line in fd:
                        line = line.split()
                        loc = line[1]
                        lport = int(loc.split(':')[1], 16)
                        st = int(line[3], 16)
                        if st != 10: # TCP_LISTEN, see include/net/tcp_states.h
                            continue
                        if lport == port:
                            inode = int(line[9])
                            break
                if inode:
                    break

            # if we didn't find the inode, there's nothing we can do about it
            if not inode:
                return

            # find the process who owns the socket
            spid = proc.pid_by_inode(inode)
            if not spid:
                return

            # let's have a look at the server exe
            sexe = proc.exe(spid)
            name = os.path.basename(sexe)
            # XXX: parse cmdline
            if name.startswith('qemu-') or name.startswith('gdbserver'):
                exe = proc.cmdline(spid)[-1]
                return os.path.join(proc.cwd(spid), exe)

        exe = findexe()

    else:
        log.error("don't know how to attach to target: %r" % target)

    # if we have a pid but no exe, just look it up in /proc/
    if pid and not exe:
        exe = proc.exe(pid)

    if not pid and not exe:
        log.error('could not find target process')

    cmd = None
    for p in ('gdb-multiarch', 'gdb'):
        if misc.which(p):
            cmd = p
            break

    if not cmd:
        log.error('no gdb installed')

    if exe:
        cmd += ' "%s"' % exe

    if pid:
        cmd += ' %d' % pid

    execute = pre + (execute or '')

    if execute:
        tmp = tempfile.NamedTemporaryFile(prefix = 'pwn', suffix = '.gdb',
                                          delete = False)
        tmp.write(execute)
        tmp.close()
        cmd += ' -x "%s" ; rm "%s"' % (tmp.name, tmp.name)

    print cmd

    misc.run_in_new_terminal(cmd)
