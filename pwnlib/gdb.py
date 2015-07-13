import os
import random
import re
import shlex
import tempfile

from . import atexit
from . import elf
from . import tubes
from .asm import make_elf, _bfdname
from .context import context, LocalContext
from .log import getLogger
from .util import misc
from .util import proc
from .qemu import get_qemu_user

log = getLogger(__name__)

@LocalContext
def debug_shellcode(data, execute=None):
    """
    Creates an ELF file, and launches it with GDB.

    Arguments:
        data(str): Assembled shellcode bytes
        kwargs(dict): Arguments passed to context (e.g. arch='arm')

    Returns:
        A ``process`` tube connected to the shellcode on stdin/stdout/stderr.
    """
    tmp_elf  = tempfile.mktemp(prefix='pwn', suffix='.elf')
    elf_data = make_elf(data)
    with open(tmp_elf,'wb+') as f:
        f.write(elf_data)
        f.flush()
    os.chmod(tmp_elf, 0777)
    atexit.register(lambda: os.unlink(tmp_elf))
    return debug(tmp_elf, execute=None, arch=context.arch)

@LocalContext
def debug(args, execute=None, exe=None, ssh=None):
    """debug(args) -> tube

    Launch a GDB server with the specified command line,
    and launches GDB to attach to it.

    Arguments:
        args: Same args as passed to pwnlib.tubes.process
        ssh: Remote ssh session to use to launch the process.
          Automatically sets up port forwarding so that gdb runs locally.

    Returns:
        A tube connected to the target process
    """
    if isinstance(args, (str, unicode)):
        args = [args]

    orig_args = args

    if context.native:
        args = ['gdbserver', '--no-disable-randomization', 'localhost:0'] + args
    else:
        qemu_port = random.randint(1024, 65535)
        args = [get_qemu_user(), '-g', str(qemu_port)] + args

    if not ssh:
        runner  = tubes.process.process
        which   = misc.which
    if ssh:
        runner  = ssh.run
        which   = ssh.which

    # Make sure gdbserver is installed
    if not which(args[0]):
        log.error("%s is not installed" % args[0])

    with context.local(log_level='debug'):
        gdbserver = runner(args)

    if context.native:
        # Process /bin/bash created; pid = 14366
        # Listening on port 34816
        process_created = gdbserver.recvline()
        gdbserver.pid   = int(process_created.split()[-1], 0)
        listening_on    = gdbserver.recvline()

        port = int(listening_on.split()[-1])
    else:
        port = qemu_port

    listener = remote = None

    if ssh:
        remote   = ssh.connect_remote('127.0.0.1', port)
        listener = tubes.listen.listen(0)
        port     = listener.lport
    elif not exe:
        exe = misc.which(orig_args[0])

    attach(('127.0.0.1', port), exe=orig_args[0], execute=execute)

    if ssh:
        remote <> listener.wait_for_connection()

    # gdbserver outputs a message when a client connects
    garbage = gdbserver.recvline(timeout=1)

    if "Remote debugging from host" not in garbage:
        gdbserver.unrecv(garbage)

    return gdbserver

def get_gdb_arch():
    return {
        'amd64': 'i386:x86-64',
        'powerpc': 'powerpc:common',
        'powerpc64': 'powerpc:common64',
        'mips64': 'mips:isa64',
        'thumb': 'arm'
    }.get(context.arch, context.arch)


@LocalContext
def attach(target, execute = None, exe = None):
    """attach(target, execute = None, exe = None, arch = None) -> None

    Start GDB in a new terminal and attach to `target`.
    :func:`pwnlib.util.proc.pidof` is used to find the PID of `target` except
    when `target` is a ``(host, port)``-pair.  In that case `target` is assumed
    to be a GDB server.

    If it is running locally and `exe` is not given we will try to find the path
    of the target binary from parsing the command line of the program running
    the GDB server (e.g. qemu or gdbserver).  Notice that if the PID is known
    (when `target` is not a GDB server) `exe` will be read from
    ``/proc/<pid>/exe``.

    If `gdb-multiarch` is installed we use that or 'gdb' otherwise.

    Arguments:
      target: The target to attach to.
      execute (str or file): GDB script to run after attaching.
      exe (str): The path of the target binary.
      arch (str): Architechture of the target binary.  If `exe` known GDB will
      detect the architechture automatically (if it is supported).

    Returns:
      :const:`None`
"""
    # if ptrace_scope is set and we're not root, we cannot attach to a running process
    try:
        ptrace_scope = open('/proc/sys/kernel/yama/ptrace_scope').read().strip()
        if ptrace_scope != '0' and os.geteuid() != 0:
            msg =  'Disable ptrace_scope to attach to running processes.\n'
            msg += 'More info: https://askubuntu.com/q/41629'
            log.warning(msg)
            return
    except IOError:
        pass

    # if execute is a file object, then read it; we probably need to run some
    # more gdb script anyway
    if execute:
        if isinstance(execute, file):
            fd = execute
            execute = fd.read()
            fd.close()

    # enable gdb.attach(p, 'continue')
    if execute and not execute.endswith('\n'):
        execute += '\n'

    # gdb script to run before `execute`
    pre = ''
    if not context.native:
        if not misc.which('gdb-multiarch'):
            log.warn_once('Cross-architecture debugging usually requires gdb-multiarch\n' \
                '$ apt-get install gdb-multiarch')
        pre += 'set endian %s\n' % context.endian
        pre += 'set architecture %s\n' % get_gdb_arch()
        # pre += 'set gnutarget ' + _bfdname() + '\n'

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
    elif isinstance(target, tubes.ssh.ssh_channel):
        if not target.pid:
            log.error("PID unknown for channel")

        shell = target.parent

        tmpfile = shell.mktemp()
        shell.upload_data(execute or '', tmpfile)

        cmd = ['ssh', '-t', '-p', str(shell.port), '-l', shell.user, shell.host]
        if shell.password:
            cmd = ['sshpass', '-p', shell.password] + cmd
        if shell.keyfile:
            cmd += ['-i', shell.keyfile]
        cmd += ['gdb %r %s -x "%s" ; rm "%s"' % (target.exe, target.pid, tmpfile, tmpfile)]

        misc.run_in_new_terminal(' '.join(cmd))
        return

    elif isinstance(target, tubes.sock.sock):
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

        exe = exe or findexe()
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
        if not os.path.isfile(exe):
            log.error('no such file: %s' % exe)
        cmd += ' "%s"' % exe

    if pid:
        cmd += ' %d' % pid

    execute = pre + (execute or '')

    if execute:
        tmp = tempfile.NamedTemporaryFile(prefix = 'pwn', suffix = '.gdb',
                                          delete = False)
        tmp.write(execute)
        tmp.close()
        atexit.register(lambda: os.unlink(tmp.name))
        cmd += ' -x "%s" ; rm "%s"' % (tmp.name, tmp.name)

    log.info('running in new terminal: %s' % cmd)
    misc.run_in_new_terminal(cmd)
    if pid:
        proc.wait_for_debugger(pid)

def ssh_gdb(ssh, process, execute = None, arch = None, **kwargs):
    if isinstance(process, (list, tuple)):
        exe = process[0]
        process = ["gdbserver", "127.0.0.1:0"] + process
    else:
        exe = process
        process = "gdbserver 127.0.0.1:0 " + process

    # Download the executable
    local_exe = os.path.basename(exe)
    ssh.download_file(exe, local_exe)

    # Run the process
    c = ssh.run(process, **kwargs)

    # Find the port for the gdb server
    c.recvuntil('port ')
    line = c.recvline().strip()
    gdbport = re.match('[0-9]+', line)
    if gdbport:
        gdbport = int(gdbport.group(0))

    l = tubes.listen.listen(0)
    forwardport = l.lport

    attach(('127.0.0.1', forwardport), execute, local_exe, arch)
    l.wait_for_connection() <> ssh.connect_remote('127.0.0.1', gdbport)
    return c

def find_module_addresses(binary, ssh=None, ulimit=False):
    """
    Cheat to find modules by using GDB.

    We can't use ``/proc/$pid/map`` since some servers forbid it.
    This breaks ``info proc`` in GDB, but ``info sharedlibrary`` still works.
    Additionally, ``info sharedlibrary`` works on FreeBSD, which may not have
    procfs enabled or accessible.

    The output looks like this:

    ::

        info proc mapping
        process 13961
        warning: unable to open /proc file '/proc/13961/maps'

        info sharedlibrary
        From        To          Syms Read   Shared Object Library
        0xf7fdc820  0xf7ff505f  Yes (*)     /lib/ld-linux.so.2
        0xf7fbb650  0xf7fc79f8  Yes         /lib32/libpthread.so.0
        0xf7e26f10  0xf7f5b51c  Yes (*)     /lib32/libc.so.6
        (*): Shared library is missing debugging information.

    Note that the raw addresses provided by ``info sharedlibrary`` are actually
    the address of the ``.text`` segment, not the image base address.

    This routine automates the entire process of:

    1. Downloading the binaries from the remote server
    2. Scraping GDB for the information
    3. Loading each library into an ELF
    4. Fixing up the base address vs. the ``.text`` segment address

    Arguments:
        binary(str): Path to the binary on the remote server
        ssh(pwnlib.tubes.tube): SSH connection through which to load the libraries.
            If left as ``None``, will use a ``pwnlib.tubes.process.process``.
        ulimit(bool): Set to ``True`` to run "ulimit -s unlimited" before GDB.

    Returns:
        A list of pwnlib.elf.ELF objects, with correct base addresses.

    Example:

    >>> with context.local(log_level=9999): # doctest: +SKIP
    ...     shell = ssh(host='bandit.labs.overthewire.org',user='bandit0',password='bandit0')
    ...     bash_libs = gdb.find_module_addresses('/bin/bash', shell)
    >>> os.path.basename(bash_libs[0].path) # doctest: +SKIP
    'libc.so.6'
    >>> hex(bash_libs[0].symbols['system']) # doctest: +SKIP
    '0x7ffff7634660'
    """
    #
    # Download all of the remote libraries
    #
    if ssh:
        runner     = ssh.run
        local_bin  = ssh.download_file(binary)
        local_elf  = elf.ELF(os.path.basename(binary))
        local_libs = ssh.libs(binary)

    else:
        runner     = tubes.process.process
        local_elf  = elf.ELF(binary)
        local_libs = local_elf.libs

    entry      = local_elf.header.e_entry

    #
    # Get the addresses from GDB
    #
    libs = {}
    cmd  = "gdb --args %s" % (binary)
    expr = re.compile(r'(0x\S+)[^/]+(.*)')

    if ulimit:
        cmd = 'sh -c "(ulimit -s unlimited; %s)"' % cmd

    cmd = shlex.split(cmd)

    with runner(cmd) as gdb:
        gdb.send("""
        set prompt
        set disable-randomization on
        break *%#x
        run
        """ % entry)
        gdb.clean(2)
        gdb.sendline('info sharedlibrary')
        lines = gdb.recvrepeat(2)

        for line in lines.splitlines():
            m = expr.match(line)
            if m:
                libs[m.group(2)] = int(m.group(1),16)
        gdb.sendline('kill')
        gdb.sendline('y')
        gdb.sendline('quit')

    #
    # Fix up all of the addresses against the .text address
    #
    rv = []

    for remote_path,text_address in sorted(libs.items()):
        # Match up the local copy to the remote path
        try:
            path     = next(p for p in local_libs.keys() if remote_path in p)
        except StopIteration:
            print "Skipping %r" % remote_path
            continue

        # Load it
        lib      = elf.ELF(path)

        # Find its text segment
        text     = lib.get_section_by_name('.text')

        # Fix the address
        lib.address = text_address - text.header.sh_addr
        rv.append(lib)

    return rv
