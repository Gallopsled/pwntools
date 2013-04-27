import pwn, os, subprocess, tempfile, time

def attach_gdb_to_pid(pid, execute = None, execute_file = None):
    if execute is not None and execute_file is not None:
        pwn.die('Both execute and execute_file can\'t be set')
    try:
        prog = pwn.proc_exe(pid)
    except OSError as e:
        pwn.die(e.strerror + ': ' + e.filename)
    if pwn.proc_tracer(pid) is not None:
        pwn.die('Program (pid: %d) is already being debugged' % pid)
    term = os.getenv('COLORTERM') or os.getenv('TERM')
    if term is None:
        pwn.die('No environment variable named (COLOR)TERM')
    term = subprocess.check_output(['/usr/bin/which', term]).strip()
    termpid = os.fork()
    if termpid == 0:
        argv = [term, '-e', 'gdb "%s" %d' % (prog, pid)]
        if execute:
            with tempfile.NamedTemporaryFile(prefix='pwn', suffix='.gdb') as tmp:
                tmp.write(execute)
                tmp.flush()
                argv[-1] += ' -x "%s"' % tmp.name
                os.execv(argv[0], argv)
        elif execute_file:
            argv[-1] += ' -x "%s"' % execute_file
            os.execv(argv[0], argv)
        else:
            os.execv(argv[0], argv)
    else:
        pwn.wait_for_debugger(pid)

def attach_gdb(prog, execute = None, execute_file = None):
    pid = pwn.pidof(prog)
    if isinstance(prog, pwn.remote):
        pwn.log.info('Looking up children of server (PID: %d)' % pid)
        pids = pwn.proc_children(pid)
        if len(pids) == 0:
            pwn.log.warning('No child processes -- attaching to the server')
        elif len(pids) == 1:
            pid = pids[0]
            pwn.log.info('Attaching to child (PID: %d)' % pid)
        else:
            pid = max(pids, key = pwn.proc_starttime)
            pwn.log.info('Attaching to youngest child (PID: %d) of %d children' % (pid, len(pids)))
    attach_gdb_to_pid(pid, execute = execute, execute_file = execute_file)
