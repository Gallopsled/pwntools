# -*- coding: utf-8 -*-
"""
During exploit development, it is frequently useful to debug the
target binary under GDB.

Pwntools makes this easy-to-do with a handful of helper routines, designed
to make your exploit-debug-update cycles much faster.

Useful Functions
----------------

- :func:`attach` - Attach to an existing process
- :func:`debug` - Start a new process under a debugger, stopped at the first instruction
- :func:`debug_shellcode` - Build a binary with the provided shellcode, and start it under a debugger

Debugging Tips
--------------

The :func:`attach` and :func:`debug` functions will likely be your bread and
butter for debugging.

Both allow you to provide a script to pass to GDB when it is started, so that
it can automatically set your breakpoints.

Attaching to Processes
~~~~~~~~~~~~~~~~~~~~~~

To attach to an existing process, just use :func:`attach`.  It is surprisingly
versatile, and can attach to a :class:`.process` for simple
binaries, or will automatically find the correct process to attach to for a
forking server, if given a :class:`.remote` object.

Spawning New Processes
~~~~~~~~~~~~~~~~~~~~~~

Attaching to processes with :func:`attach` is useful, but the state the process
is in may vary.  If you need to attach to a process very early, and debug it from
the very first instruction (or even the start of ``main``), you instead should use
:func:`debug`.

When you use :func:`debug`, the return value is a :class:`.tube` object
that you interact with exactly like normal.

Tips and Troubleshooting
------------------------

``NOPTRACE`` magic argument
~~~~~~~~~~~~~~~~~~~~~~~~~~~

It's quite cumbersom to comment and un-comment lines containing `attach`.

You can cause these lines to be a no-op by running your script with the
``NOPTRACE`` argument appended, or with ``PWNLIB_NOPTRACE=1`` in the environment.

::

    $ python exploit.py NOPTRACE
    [+] Starting local process '/bin/bash': Done
    [!] Skipping debug attach since context.noptrace==True
    ...

Kernel Yama ptrace_scope
~~~~~~~~~~~~~~~~~~~~~~~~

The Linux kernel v3.4 introduced a security mechanism called ``ptrace_scope``,
which is intended to prevent processes from debugging eachother unless there is
a direct parent-child relationship.

This causes some issues with the normal Pwntools workflow, since the process
heirarchy looks like this:

::

    python ---> target
           `--> gdb

Note that ``python`` is the parent of ``target``, not ``gdb``.

In order to avoid this being a problem, Pwntools uses the function
``prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY)``.  This disables Yama
for any processes launched by Pwntools via :class:`.process` or via
:meth:`.ssh.process`.

Older versions of Pwntools did not perform the ``prctl`` step, and
required that the Yama security feature was disabled systemwide, which
requires ``root`` access.

Member Documentation
===============================
"""
from __future__ import absolute_import
from __future__ import division

import os
import random
import re
import shlex
import six
import tempfile
import time

from pwnlib import adb
from pwnlib import atexit
from pwnlib import elf
from pwnlib import qemu
from pwnlib import tubes
from pwnlib.asm import _bfdname
from pwnlib.asm import make_elf
from pwnlib.asm import make_elf_from_assembly
from pwnlib.context import LocalContext
from pwnlib.context import context
from pwnlib.log import getLogger
from pwnlib.util import misc
from pwnlib.util import proc

log = getLogger(__name__)

@LocalContext
def debug_assembly(asm, gdbscript=None, vma=None):
    """debug_assembly(asm, gdbscript=None, vma=None) -> tube

    Creates an ELF file, and launches it under a debugger.

    This is identical to debug_shellcode, except that
    any defined symbols are available in GDB, and it
    saves you the explicit call to asm().

    Arguments:
        asm(str): Assembly code to debug
        gdbscript(str): Script to run in GDB
        vma(int): Base address to load the shellcode at
        **kwargs: Override any :obj:`pwnlib.context.context` values.

    Returns:
        :class:`.process`

    Example:

        .. code-block:: python

            assembly = shellcraft.echo("Hello world!\n")
            io = gdb.debug_assembly(assembly)
            io.recvline()
            # 'Hello world!'
    """
    tmp_elf = make_elf_from_assembly(asm, vma=vma, extract=False)
    os.chmod(tmp_elf, 0o777)

    atexit.register(lambda: os.unlink(tmp_elf))

    if context.os == 'android':
        android_path = '/data/data/%s' % os.path.basename(tmp_elf)
        adb.push(tmp_elf, android_path)
        tmp_elf = android_path

    return debug(tmp_elf, gdbscript=gdbscript, arch=context.arch)

@LocalContext
def debug_shellcode(data, gdbscript=None, vma=None):
    """
    Creates an ELF file, and launches it under a debugger.

    Arguments:
        data(str): Assembled shellcode bytes
        gdbscript(str): Script to run in GDB
        vma(int): Base address to load the shellcode at
        **kwargs: Override any :obj:`pwnlib.context.context` values.

    Returns:
        :class:`.process`

    Example:

        .. code-block:: python

            assembly = shellcraft.echo("Hello world!\n")
            shellcode = asm(assembly)
            io = gdb.debug_shellcode(shellcode)
            io.recvline()
            # 'Hello world!'
    """
    if isinstance(data, unicode):
        log.error("Shellcode is cannot be unicode.  Did you mean debug_assembly?")
    tmp_elf = make_elf(data, extract=False, vma=vma)
    os.chmod(tmp_elf, 0o777)

    atexit.register(lambda: os.unlink(tmp_elf))

    if context.os == 'android':
        android_path = '/data/data/%s' % os.path.basename(tmp_elf)
        adb.push(tmp_elf, android_path)
        tmp_elf = android_path

    return debug(tmp_elf, gdbscript=gdbscript, arch=context.arch)

def _gdbserver_args(pid=None, path=None, args=None, which=None):
    """_gdbserver_args(pid=None, path=None) -> list

    Sets up a listening gdbserver, to either connect to the specified
    PID, or launch the specified binary by its full path.

    Arguments:
        pid(int): Process ID to attach to
        path(str): Process to launch
        args(list): List of arguments to provide on the debugger command line
        which(callaable): Function to find the path of a binary.

    Returns:
        A list of arguments to invoke gdbserver.
    """
    if [pid, path, args].count(None) != 2:
        log.error("Must specify exactly one of pid, path, or args")

    if not which:
        log.error("Must specify which.")

    gdbserver = ''

    if not args:
        args = [str(path or pid)]

    # Android targets have a distinct gdbserver
    if context.bits == 64:
        gdbserver = which('gdbserver64')

    if not gdbserver:
        gdbserver = which('gdbserver')

    if not gdbserver:
        log.error("gdbserver is not installed")

    orig_args = args

    gdbserver_args = [gdbserver, '--multi']
    if context.aslr:
        gdbserver_args += ['--no-disable-randomization']
    else:
        log.warn_once("Debugging process with ASLR disabled")

    if pid:
        gdbserver_args += ['--once', '--attach']

    gdbserver_args += ['localhost:0']
    gdbserver_args += args

    return gdbserver_args

def _gdbserver_port(gdbserver, ssh):
    which = _get_which(ssh)

    # Process /bin/bash created; pid = 14366
    # Listening on port 34816
    process_created = gdbserver.recvline()

    if process_created.startswith('ERROR:'):
        raise ValueError(
            'Failed to spawn process under gdbserver. gdbserver error message: %s' % process_created
        )

    gdbserver.pid   = int(process_created.split()[-1], 0)

    listening_on = ''
    while 'Listening' not in listening_on:
        listening_on    = gdbserver.recvline()

    port = int(listening_on.split()[-1])

    # Set up port forarding for SSH
    if ssh:
        remote   = ssh.connect_remote('127.0.0.1', port)
        listener = tubes.listen.listen(0)
        port     = listener.lport

        # Disable showing GDB traffic when debugging verbosity is increased
        remote.level = 'error'
        listener.level = 'error'

        # Hook them up
        remote.connect_both(listener)

    # Set up port forwarding for ADB
    elif context.os == 'android':
        adb.forward(port)

    return port

def _get_which(ssh=None):
    if ssh:                        return ssh.which
    elif context.os == 'android':  return adb.which
    else:                          return misc.which

def _get_runner(ssh=None):
    if ssh:                        return ssh.process
    elif context.os == 'android':  return adb.process
    else:                          return tubes.process.process

@LocalContext
def debug(args, gdbscript=None, exe=None, ssh=None, env=None, sysroot=None, **kwargs):
    """debug(args) -> tube

    Launch a GDB server with the specified command line,
    and launches GDB to attach to it.

    Arguments:
        args(list): Arguments to the process, similar to :class:`.process`.
        gdbscript(str): GDB script to run.
        exe(str): Path to the executable on disk
        env(dict): Environment to start the binary in
        ssh(:class:`.ssh`): Remote ssh session to use to launch the process.
        sysroot(str): Foreign-architecture sysroot, used for QEMU-emulated binaries
            and Android targets.

    Returns:
        :class:`.process` or :class:`.ssh_channel`: A tube connected to the target process

    Notes:

        The debugger is attached automatically, and you can debug everything
        from the very beginning.  This requires that both ``gdb`` and ``gdbserver``
        are installed on your machine.

        When GDB opens via :func:`debug`, it will initially be stopped on the very first
        instruction of the dynamic linker (``ld.so``) for dynamically-linked binaries.

        Only the target binary and the linker will be loaded in memory, so you cannot
        set breakpoints on shared library routines like ``malloc`` since ``libc.so``
        has not even been loaded yet.

        There are several ways to handle this:

        1. Set a breakpoint on the executable's entry point (generally, ``_start``)
            - This is only invoked after all of the required shared libraries
              are loaded.
            - You can generally get the address via the GDB command ``info file``.
        2. Use pending breakpoints via ``set breakpoint pending on``
            - This has the side-effect of setting breakpoints for **every** function
              which matches the name.  For ``malloc``, this will generally set a
              breakpoint in the executable's PLT, in the linker's internal ``malloc``,
              and eventaully in ``libc``'s malloc.
        3. Wait for libraries to be loaded with ``set stop-on-solib-event 1``
            - There is no way to stop on any specific library being loaded, and sometimes
              multiple libraries are loaded and only a single breakpoint is issued.
            - Generally, you just add a few ``continue`` commands until things are set up
              the way you want it to be.

    Examples:

        .. code-block:: python

            # Create a new process, and stop it at 'main'
            io = gdb.debug('bash', '''
            break main
            continue
            ''')

            # Send a command to Bash
            io.sendline("echo hello")

            # Interact with the process
            io.interactive()

        .. code-block:: python

            # Create a new process, and stop it at 'main'
            io = gdb.debug('bash', '''
            # Wait until we hit the main executable's entry point
            break _start
            continue

            # Now set breakpoint on shared library routines
            break malloc
            break free
            continue
            ''')

            # Send a command to Bash
            io.sendline("echo hello")

            # Interact with the process
            io.interactive()

        You can use :func:`debug` to spawn new processes on remote machines as well,
        by using the ``ssh=`` keyword to pass in your :class:`.ssh` instance.

        .. code-block:: python

            # Connect to the SSH server
            shell = ssh('passcode', 'pwnable.kr', 2222, password='guest')

            # Start a process on the server
            io = gdb.debug(['bash'],
                            ssh=shell,
                            gdbscript='''
            break main
            continue
            ''')

            # Send a command to Bash
            io.sendline("echo hello")

            # Interact with the process
            io.interactive()
    """
    if isinstance(args, (int, tubes.process.process, tubes.ssh.ssh_channel)):
        log.error("Use gdb.attach() to debug a running process")

    if env is None:
        env = os.environ

    if isinstance(args, (str, unicode)):
        args = [args]

    orig_args = args

    runner = _get_runner(ssh)
    which  = _get_which(ssh)
    gdbscript = gdbscript or ''

    if context.noptrace:
        log.warn_once("Skipping debugger since context.noptrace==True")
        return runner(args, executable=exe, env=env)

    if ssh or context.native or (context.os == 'android'):
        args = _gdbserver_args(args=args, which=which)
    else:
        qemu_port = random.randint(1024, 65535)
        qemu_user = qemu.user_path()
        sysroot = sysroot or qemu.ld_prefix(env=env)
        if not qemu_user:
            log.error("Cannot debug %s binaries without appropriate QEMU binaries" % context.arch)
        args = [qemu_user, '-g', str(qemu_port)] + args

    # Use a sane default sysroot for Android
    if not sysroot and context.os == 'android':
        sysroot = 'remote:/'

    # Make sure gdbserver/qemu is installed
    if not which(args[0]):
        log.error("%s is not installed" % args[0])

    exe = exe or which(orig_args[0])
    if not exe:
        log.error("%s does not exist" % orig_args[0])
    else:
        gdbscript = 'file %s\n%s' % (exe, gdbscript)

    # Start gdbserver/qemu
    # (Note: We override ASLR here for the gdbserver process itself.)
    gdbserver = runner(args, env=env, aslr=1, **kwargs)

    # Set the .executable on the process object.
    gdbserver.executable = which(orig_args[0])

    # Find what port we need to connect to
    if context.native or (context.os == 'android'):
        port = _gdbserver_port(gdbserver, ssh)
    else:
        port = qemu_port

    host = '127.0.0.1'
    if not ssh and context.os == 'android':
        host = context.adb_host

    attach((host, port), exe=exe, gdbscript=gdbscript, need_ptrace_scope = False, ssh=ssh, sysroot=sysroot)

    # gdbserver outputs a message when a client connects
    garbage = gdbserver.recvline(timeout=1)
    
    # Some versions of gdbserver output an additional message
    garbage2 = gdbserver.recvline_startswith("Remote debugging from host ", timeout=1)

    return gdbserver

def get_gdb_arch():
    return {
        'amd64': 'i386:x86-64',
        'powerpc': 'powerpc:common',
        'powerpc64': 'powerpc:common64',
        'mips64': 'mips:isa64',
        'thumb': 'arm'
    }.get(context.arch, context.arch)

def binary():
    """binary() -> str

    Returns:
        str: Path to the appropriate ``gdb`` binary to use.

    Example:

        >>> gdb.binary() # doctest: +SKIP
        '/usr/bin/gdb'
    """
    gdb = misc.which('pwntools-gdb') or misc.which('gdb')

    if not context.native:
        multiarch = misc.which('gdb-multiarch')

        if multiarch:
            return multiarch
        log.warn_once('Cross-architecture debugging usually requires gdb-multiarch\n' \
                      '$ apt-get install gdb-multiarch')

    if not gdb:
        log.error('GDB is not installed\n'
                  '$ apt-get install gdb')

    return gdb

@LocalContext
def attach(target, gdbscript = None, exe = None, need_ptrace_scope = True, gdb_args = None, ssh = None, sysroot = None):
    """attach(target, gdbscript = None, exe = None, arch = None, ssh = None) -> None

    Start GDB in a new terminal and attach to `target`.

    Arguments:
        target: The target to attach to.
        gdbscript(:obj:`str` or :obj:`file`): GDB script to run after attaching.
        exe(str): The path of the target binary.
        arch(str): Architechture of the target binary.  If `exe` known GDB will
          detect the architechture automatically (if it is supported).
        gdb_args(list): List of additional arguments to pass to GDB.
        sysroot(str): Foreign-architecture sysroot, used for QEMU-emulated binaries
            and Android targets.

    Returns:
        PID of the GDB process (or the window which it is running in).

    Notes:

        The ``target`` argument is very robust, and can be any of the following:

        :obj:`int`
            PID of a process
        :obj:`str`
            Process name.  The youngest process is selected.
        :obj:`tuple`
            Host, port pair of a listening ``gdbserver``
        :class:`.process`
            Process to connect to
        :class:`.sock`
            Connected socket. The executable on the other end of the connection is attached to.
            Can be any socket type, including :class:`.listen` or :class:`.remote`.
        :class:`.ssh_channel`
            Remote process spawned via :meth:`.ssh.process`.
            This will use the GDB installed on the remote machine.
            If a password is required to connect, the ``sshpass`` program must be installed.

    Examples:

        .. code-block:: python

            # Attach directly to pid 1234
            gdb.attach(1234)

        .. code-block:: python

            # Attach to the youngest "bash" process
            gdb.attach('bash')

        .. code-block:: python

            # Start a process
            bash = process('bash')

            # Attach the debugger
            gdb.attach(bash, '''
            set follow-fork-mode child
            break execve
            continue
            ''')

            # Interact with the process
            bash.sendline('whoami')

        .. code-block:: python

            # Start a forking server
            server = process(['socat', 'tcp-listen:1234,fork,reuseaddr', 'exec:/bin/sh'])

            # Connect to the server
            io = remote('localhost', 1234)

            # Connect the debugger to the server-spawned process
            gdb.attach(io, '''
            break exit
            continue
            ''')

            # Talk to the spawned 'sh'
            io.sendline('exit')

        .. code-block:: python

            # Connect to the SSH server
            shell = ssh('bandit0', 'bandit.labs.overthewire.org', password='bandit0', port=2220)

            # Start a process on the server
            cat = shell.process(['cat'])

            # Attach a debugger to it
            gdb.attach(cat, '''
            break exit
            continue
            ''')

            # Cause `cat` to exit
            cat.close()
    """
    if context.noptrace:
        log.warn_once("Skipping debug attach since context.noptrace==True")
        return

    # if gdbscript is a file object, then read it; we probably need to run some
    # more gdb script anyway
    if hasattr(gdbscript, 'read'):
        with gdbscript:
            gdbscript = gdbscript.read()

    # enable gdb.attach(p, 'continue')
    if gdbscript and not gdbscript.endswith('\n'):
        gdbscript += '\n'

    # Use a sane default sysroot for Android
    if not sysroot and context.os == 'android':
        sysroot = 'remote:/'

    # gdb script to run before `gdbscript`
    pre = ''
    if not context.native:
        pre += 'set endian %s\n' % context.endian
        pre += 'set architecture %s\n' % get_gdb_arch()
        if sysroot:
            pre += 'set sysroot %s\n' % sysroot

        if context.os == 'android':
            pre += 'set gnutarget ' + _bfdname() + '\n'

    # let's see if we can find a pid to attach to
    pid = None
    if   isinstance(target, six.integer_types):
        # target is a pid, easy peasy
        pid = target
    elif isinstance(target, str):
        # pidof picks the youngest process
        pidof = proc.pidof

        if context.os == 'android':
            pidof = adb.pidof

        pids = pidof(target)
        if not pids:
            log.error('No such process: %s' % target)
        pid = pids[0]
        log.info('Attaching to youngest process "%s" (PID = %d)' %
                 (target, pid))
    elif isinstance(target, tubes.ssh.ssh_channel):
        if not target.pid:
            log.error("PID unknown for channel")

        shell = target.parent

        tmpfile = shell.mktemp()
        gdbscript = 'shell rm %s\n%s' % (tmpfile, gdbscript)
        shell.upload_data(gdbscript or '', tmpfile)

        cmd = ['ssh', '-C', '-t', '-p', str(shell.port), '-l', shell.user, shell.host]
        if shell.password:
            if not misc.which('sshpass'):
                log.error("sshpass must be installed to debug ssh processes")
            cmd = ['sshpass', '-p', shell.password] + cmd
        if shell.keyfile:
            cmd += ['-i', shell.keyfile]
        cmd += ['gdb -q %r %s -x "%s"' % (target.executable,
                                       target.pid,
                                       tmpfile)]

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
        exe = exe or target.executable
    elif isinstance(target, tuple) and len(target) == 2:
        host, port = target

        if context.os != 'android':
            pre += 'target remote %s:%d\n' % (host, port)
        else:
            # Android debugging is done over gdbserver, which can't follow
            # new inferiors (tldr; follow-fork-mode child) unless it is run
            # in extended-remote mode.
            pre += 'target extended-remote %s:%d\n' % (host, port)
            pre += 'set detach-on-fork off\n'

        def findexe():
            for spid in proc.pidof(target):
                sexe = proc.exe(spid)
                name = os.path.basename(sexe)
                # XXX: parse cmdline
                if name.startswith('qemu-') or name.startswith('gdbserver'):
                    exe = proc.cmdline(spid)[-1]
                    return os.path.join(proc.cwd(spid), exe)

        exe = exe or findexe()
    elif isinstance(target, elf.corefile.Corefile):
        pre += 'target core %s\n' % target.path
    else:
        log.error("don't know how to attach to target: %r" % target)

    # if we have a pid but no exe, just look it up in /proc/
    if pid and not exe:
        exe_fn = proc.exe
        if context.os == 'android':
            exe_fn = adb.proc_exe
        exe = exe_fn(pid)

    if not pid and not exe:
        log.error('could not find target process')

    if exe:
        # The 'file' statement should go first
        pre = 'file %s\n%s' % (exe, pre)

    cmd = binary()

    if gdb_args:
        cmd += ' '
        cmd += ' '.join(gdb_args)

    if context.gdbinit:
        cmd += ' -nh '                     # ignore ~/.gdbinit
        cmd += ' -x %s ' % context.gdbinit # load custom gdbinit

    cmd += ' -q '

    if exe and context.native:
        if ssh:
            ssh.download_file(exe)
            exe = os.path.basename(exe)
        if not os.path.isfile(exe):
            log.error('No such file: %s' % exe)
        cmd += ' "%s"' % exe

    if pid and not context.os == 'android':
        cmd += ' %d' % pid

    if context.os == 'android' and pid:
        runner  = _get_runner()
        which   = _get_which()
        gdb_cmd = _gdbserver_args(pid=pid, which=which)
        gdbserver = runner(gdb_cmd)
        port    = _gdbserver_port(gdbserver, None)
        host    = context.adb_host
        pre    += 'target extended-remote %s:%i\n' % (context.adb_host, port)

        # gdbserver on Android sets 'detach-on-fork on' which breaks things
        # when you're trying to debug anything that forks.
        pre += 'set detach-on-fork off\n'

    gdbscript = pre + (gdbscript or '')

    if gdbscript:
        tmp = tempfile.NamedTemporaryFile(prefix = 'pwn', suffix = '.gdb',
                                          delete = False, mode = 'w+')
        log.debug('Wrote gdb script to %r\n%s' % (tmp.name, gdbscript))
        gdbscript = 'shell rm %s\n%s' % (tmp.name, gdbscript)

        tmp.write(gdbscript)
        tmp.close()
        cmd += ' -x "%s"' % (tmp.name)

    log.info('running in new terminal: %s' % cmd)

    gdb_pid = misc.run_in_new_terminal(cmd)

    if pid and context.native:
        proc.wait_for_debugger(pid)

    return gdb_pid

def ssh_gdb(ssh, argv, gdbscript = None, arch = None, **kwargs):
    if not isinstance(argv, (list, tuple)):
        argv = [argv]

    exe = argv[0]
    argv = ["gdbserver", "--multi", "127.0.0.1:0"] + argv

    # Download the executable
    local_exe = os.path.basename(exe)
    ssh.download_file(ssh.which(exe), local_exe)

    # Run the process
    c = ssh.process(argv, **kwargs)

    # Find the port for the gdb server
    c.recvuntil('port ')
    line = c.recvline().strip()
    gdbport = re.match(b'[0-9]+', line)
    if gdbport:
        gdbport = int(gdbport.group(0))

    l = tubes.listen.listen(0)
    forwardport = l.lport

    attach(('127.0.0.1', forwardport), gdbscript, local_exe, arch, ssh=ssh)
    l.wait_for_connection().connect_both(ssh.connect_remote('127.0.0.1', gdbport))
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
            If left as :const:`None`, will use a :class:`pwnlib.tubes.process.process`.
        ulimit(bool): Set to :const:`True` to run "ulimit -s unlimited" before GDB.

    Returns:
        A list of pwnlib.elf.ELF objects, with correct base addresses.

    Example:

    >>> with context.local(log_level=9999): # doctest: +SKIP
    ...     shell = ssh(host='bandit.labs.overthewire.org',user='bandit0',password='bandit0', port=2220)
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
    cmd  = "gdb -q --args %s" % (binary)
    expr = re.compile(r'(0x\S+)[^/]+(.*)')

    if ulimit:
        cmd = 'sh -c "(ulimit -s unlimited; %s)"' % cmd

    cmd = shlex.split(cmd)

    with runner(cmd) as gdb:
        if context.aslr:
            gdb.sendline('set disable-randomization off')
        gdb.send("""
        set prompt
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
            print("Skipping %r" % remote_path)
            continue

        # Load it
        lib      = elf.ELF(path)

        # Find its text segment
        text     = lib.get_section_by_name('.text')

        # Fix the address
        lib.address = text_address - text.header.sh_addr
        rv.append(lib)

    return rv

def corefile(process):
    r"""Drops a core file for the process.

    Arguments:
        process: Process to dump

    Returns:
        :class:`.Core`: The generated core file
    """

    if context.noptrace:
        log.warn_once("Skipping corefile since context.noptrace==True")
        return

    corefile_path = './core.%s.%i' % (os.path.basename(process.executable),
                                    process.pid)

    # Due to https://sourceware.org/bugzilla/show_bug.cgi?id=16092
    # will disregard coredump_filter, and will not dump private mappings.
    if version() < (7,11):
        log.warn_once('The installed GDB (%s) does not emit core-dumps which '
                      'contain all of the data in the process.\n'
                      'Upgrade to GDB >= 7.11 for better core-dumps.' % binary())

    # This is effectively the same as what the 'gcore' binary does
    gdb_args = ['-batch',
                '-q',
                '--nx',
                '-ex', '"set pagination off"',
                '-ex', '"set height 0"',
                '-ex', '"set width 0"',
                '-ex', '"set use-coredump-filter on"',
                '-ex', '"generate-core-file %s"' % corefile_path,
                '-ex', 'detach']

    with context.local(terminal = ['sh', '-c']):
        with context.quiet:
            pid = attach(process, gdb_args=gdb_args)
            os.waitpid(pid, 0)

    return elf.corefile.Core(corefile_path)

def version(program='gdb'):
    """Gets the current GDB version.

    Note:
        Requires that GDB version meets the following format:

        ``GNU gdb (GDB) 7.12``

    Returns:
        tuple: A tuple containing the version numbers

    Example:

        >>> (7,0) <= gdb.version() <= (8,0)
        True
    """
    program = misc.which(program)
    expr = br'([0-9]+\.?)+'

    with tubes.process.process([program, '--version'], level='error') as gdb:
        version = gdb.recvline()

    versions = re.search(expr, version).group()

    return tuple(map(int, versions.split(b'.')))
