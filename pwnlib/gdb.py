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

Using GDB Python API
~~~~~~~~~~~~~~~~~~~~

GDB provides Python API, which is documented at
https://sourceware.org/gdb/onlinedocs/gdb/Python-API.html. Pwntools allows you
to call it right from the exploit, without having to write a gdbscript. This is
useful for inspecting program state, e.g. asserting that leaked values are
correct, or that certain packets trigger a particular code path or put the heap
in a desired state.

Pass ``api=True`` to :func:`attach` or :func:`debug` in order to enable GDB
Python API access. Pwntools will then connect to GDB using RPyC library:
https://rpyc.readthedocs.io/en/latest/.

At the moment this is an experimental feature with the following limitations:

- Only Python 3 is supported.

  Well, technically that's not quite true. The real limitation is that your
  GDB's Python interpreter major version should be the same as that of
  Pwntools. However, most GDBs use Python 3 nowadays.

  Different minor versions are allowed as long as no incompatible values are
  sent in either direction. See
  https://rpyc.readthedocs.io/en/latest/install.html#cross-interpreter-compatibility
  for more information.

  Use

  ::

      $ gdb -batch -ex 'python import sys; print(sys.version)'

  in order to check your GDB's Python version.
- If your GDB uses a different Python interpreter than Pwntools (for example,
  because you run Pwntools out of a virtualenv), you should install ``rpyc``
  package into its ``sys.path``. Use

  ::

      $ gdb -batch -ex 'python import rpyc'

  in order to check whether this is necessary.
- Only local processes are supported.
- It is not possible to tell whether ``gdb.execute('continue')`` will be
  executed synchronously or asynchronously (in gdbscripts it is always
  synchronous). Therefore it is recommended to use either the explicitly
  synchronous :func:`pwnlib.gdb.Gdb.continue_and_wait` or the explicitly
  asynchronous :func:`pwnlib.gdb.Gdb.continue_nowait` instead.

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
hierarchy looks like this:

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

from contextlib import contextmanager
import os
import platform
import psutil
import random
import re
import shlex
import six
import six.moves
import socket
import tempfile
from threading import Event
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
from pwnlib.timeout import Timeout
from pwnlib.util import misc
from pwnlib.util import packing
from pwnlib.util import proc

log = getLogger(__name__)

@LocalContext
def debug_assembly(asm, gdbscript=None, vma=None, api=False):
    r"""debug_assembly(asm, gdbscript=None, vma=None, api=False) -> tube

    Creates an ELF file, and launches it under a debugger.

    This is identical to debug_shellcode, except that
    any defined symbols are available in GDB, and it
    saves you the explicit call to asm().

    Arguments:
        asm(str): Assembly code to debug
        gdbscript(str): Script to run in GDB
        vma(int): Base address to load the shellcode at
        api(bool): Enable access to GDB Python API
        \**kwargs: Override any :obj:`pwnlib.context.context` values.

    Returns:
        :class:`.process`

    Example:

    >>> assembly = shellcraft.echo("Hello world!\n")
    >>> io = gdb.debug_assembly(assembly)
    >>> io.recvline()
    b'Hello world!\n'
    """
    tmp_elf = make_elf_from_assembly(asm, vma=vma, extract=False)
    os.chmod(tmp_elf, 0o777)

    atexit.register(lambda: os.unlink(tmp_elf))

    if context.os == 'android':
        android_path = '/data/data/%s' % os.path.basename(tmp_elf)
        adb.push(tmp_elf, android_path)
        tmp_elf = android_path

    return debug(tmp_elf, gdbscript=gdbscript, arch=context.arch, api=api)

@LocalContext
def debug_shellcode(data, gdbscript=None, vma=None, api=False):
    r"""debug_shellcode(data, gdbscript=None, vma=None, api=False) -> tube
    Creates an ELF file, and launches it under a debugger.

    Arguments:
        data(str): Assembled shellcode bytes
        gdbscript(str): Script to run in GDB
        vma(int): Base address to load the shellcode at
        api(bool): Enable access to GDB Python API
        \**kwargs: Override any :obj:`pwnlib.context.context` values.

    Returns:
        :class:`.process`

    Example:

    >>> assembly = shellcraft.echo("Hello world!\n")
    >>> shellcode = asm(assembly)
    >>> io = gdb.debug_shellcode(shellcode)
    >>> io.recvline()
    b'Hello world!\n'
    """
    if isinstance(data, six.text_type):
        log.error("Shellcode is cannot be unicode.  Did you mean debug_assembly?")
    tmp_elf = make_elf(data, extract=False, vma=vma)
    os.chmod(tmp_elf, 0o777)

    atexit.register(lambda: os.unlink(tmp_elf))

    if context.os == 'android':
        android_path = '/data/data/%s' % os.path.basename(tmp_elf)
        adb.push(tmp_elf, android_path)
        tmp_elf = android_path

    return debug(tmp_elf, gdbscript=gdbscript, arch=context.arch, api=api)

def _gdbserver_args(pid=None, path=None, args=None, which=None, env=None):
    """_gdbserver_args(pid=None, path=None, args=None, which=None, env=None) -> list

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

    if env is not None:
        env_args = []
        for key in tuple(env):
            if key.startswith(b'LD_'): # LD_PRELOAD / LD_LIBRARY_PATH etc.
                env_args.append(b'%s=%s' % (key, env.pop(key)))
            else:
                env_args.append(b'%s=%s' % (key, env[key]))
        gdbserver_args += ['--wrapper', 'env', '-i'] + env_args + ['--']

    gdbserver_args += ['localhost:0']
    gdbserver_args += args

    return gdbserver_args

def _gdbserver_port(gdbserver, ssh):
    which = _get_which(ssh)

    # Process /bin/bash created; pid = 14366
    # Listening on port 34816
    process_created = gdbserver.recvline()

    if process_created.startswith(b'ERROR:'):
        raise ValueError(
            'Failed to spawn process under gdbserver. gdbserver error message: %r' % process_created
        )

    try:
        gdbserver.pid   = int(process_created.split()[-1], 0)
    except ValueError:
        log.error('gdbserver did not output its pid (maybe chmod +x?): %r', process_created)

    listening_on = b''
    while b'Listening' not in listening_on:
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
def debug(args, gdbscript=None, exe=None, ssh=None, env=None, sysroot=None, api=False, **kwargs):
    r"""
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
        api(bool): Enable access to GDB Python API.

    Returns:
        :class:`.process` or :class:`.ssh_channel`: A tube connected to the target process.
        When ``api=True``, ``gdb`` member of the returned object contains a :class:`Gdb`
        instance.

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

        Create a new process, and stop it at 'main'

        >>> io = gdb.debug('bash', '''
        ... break main
        ... continue
        ... ''')

        Send a command to Bash

        >>> io.sendline(b"echo hello")
        >>> io.recvline()
        b'hello\n'

        Interact with the process

        >>> io.interactive() # doctest: +SKIP
        >>> io.close()

        Create a new process, and stop it at '_start'

        >>> io = gdb.debug('bash', '''
        ... # Wait until we hit the main executable's entry point
        ... break _start
        ... continue
        ...
        ... # Now set breakpoint on shared library routines
        ... break malloc
        ... break free
        ... continue
        ... ''')

        Send a command to Bash

        >>> io.sendline(b"echo hello")
        >>> io.recvline()
        b'hello\n'

        Interact with the process

        >>> io.interactive() # doctest: +SKIP
        >>> io.close()

    Using GDB Python API:

    .. doctest
       :skipif: six.PY2

        Debug a new process

        >>> io = gdb.debug(['echo', 'foo'], api=True)

        Stop at 'write'

        >>> bp = io.gdb.Breakpoint('write', temporary=True)
        >>> io.gdb.continue_and_wait()

        Dump 'count'

        >>> count = io.gdb.parse_and_eval('$rdx')
        >>> long = io.gdb.lookup_type('long')
        >>> int(count.cast(long))
        4

        Resume the program

        >>> io.gdb.continue_nowait()
        >>> io.recvline()
        b'foo\n'


    Using SSH:

        You can use :func:`debug` to spawn new processes on remote machines as well,
        by using the ``ssh=`` keyword to pass in your :class:`.ssh` instance.

        Connect to the SSH server and start a process on the server

        >>> shell = ssh('travis', 'example.pwnme', password='demopass')
        >>> io = gdb.debug(['whoami'],
        ...                 ssh = shell,
        ...                 gdbscript = '''
        ... break main
        ... continue
        ... ''')

        Send a command to Bash

        >>> io.sendline(b"echo hello")

        Interact with the process
        >>> io.interactive() # doctest: +SKIP
        >>> io.close()
    """
    if isinstance(args, six.integer_types + (tubes.process.process, tubes.ssh.ssh_channel)):
        log.error("Use gdb.attach() to debug a running process")

    if isinstance(args, (bytes, six.text_type)):
        args = [args]

    orig_args = args

    runner = _get_runner(ssh)
    which  = _get_which(ssh)
    gdbscript = gdbscript or ''

    if api and runner is not tubes.process.process:
        raise ValueError('GDB Python API is supported only for local processes')

    args, env = misc.normalize_argv_env(args, env, log)
    if env:
        env = {bytes(k): bytes(v) for k, v in env}

    if context.noptrace:
        log.warn_once("Skipping debugger since context.noptrace==True")
        return runner(args, executable=exe, env=env)

    if ssh or context.native or (context.os == 'android'):
        args = _gdbserver_args(args=args, which=which, env=env)
    else:
        qemu_port = random.randint(1024, 65535)
        qemu_user = qemu.user_path()
        sysroot = sysroot or qemu.ld_prefix(env=env)
        if not qemu_user:
            log.error("Cannot debug %s binaries without appropriate QEMU binaries" % context.arch)
        if context.os == 'baremetal':
            qemu_args = [qemu_user, '-S', '-gdb', 'tcp::' + str(qemu_port)]
        else:
            qemu_args = [qemu_user, '-g', str(qemu_port)]
        if sysroot:
            qemu_args += ['-L', sysroot]
        args = qemu_args + args

    # Use a sane default sysroot for Android
    if not sysroot and context.os == 'android':
        sysroot = 'remote:/'

    # Make sure gdbserver/qemu is installed
    if not which(args[0]):
        log.error("%s is not installed" % args[0])

    if not ssh:
        exe = exe or which(orig_args[0])
        if not (exe and os.path.exists(exe)):
            log.error("%s does not exist" % exe)

    # Start gdbserver/qemu
    # (Note: We override ASLR here for the gdbserver process itself.)
    gdbserver = runner(args, env=env, aslr=1, **kwargs)

    # Set the .executable on the process object.
    gdbserver.executable = exe

    # Find what port we need to connect to
    if context.native or (context.os == 'android'):
        port = _gdbserver_port(gdbserver, ssh)
    else:
        port = qemu_port

    host = '127.0.0.1'
    if not ssh and context.os == 'android':
        host = context.adb_host

    tmp = attach((host, port), exe=exe, gdbscript=gdbscript, ssh=ssh, sysroot=sysroot, api=api)
    if api:
        _, gdb = tmp
        gdbserver.gdb = gdb

    # gdbserver outputs a message when a client connects
    garbage = gdbserver.recvline(timeout=1)

    # Some versions of gdbserver output an additional message
    garbage2 = gdbserver.recvline_startswith(b"Remote debugging from host ", timeout=2)

    return gdbserver

def get_gdb_arch():
    return {
        'amd64': 'i386:x86-64',
        'powerpc': 'powerpc:common',
        'powerpc64': 'powerpc:common64',
        'mips64': 'mips:isa64',
        'thumb': 'arm',
        'sparc64': 'sparc:v9'
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
        log.warn_once('Cross-architecture debugging usually requires gdb-multiarch\n'
                      '$ apt-get install gdb-multiarch')

    if not gdb:
        log.error('GDB is not installed\n'
                  '$ apt-get install gdb')

    return gdb

class Breakpoint:
    """Mirror of ``gdb.Breakpoint`` class.

    See https://sourceware.org/gdb/onlinedocs/gdb/Breakpoints-In-Python.html
    for more information.
    """

    def __init__(self, conn, *args, **kwargs):
        """Do not create instances of this class directly.

        Use ``pwnlib.gdb.Gdb.Breakpoint`` instead.
        """
        # Creates a real breakpoint and connects it with this mirror
        self.conn = conn
        self.server_breakpoint = conn.root.set_breakpoint(
            self, hasattr(self, 'stop'), *args, **kwargs)

    def __getattr__(self, item):
        """Return attributes of the real breakpoint."""
        if item in (
                '____id_pack__',
                '__name__',
                '____conn__',
                'stop',
        ):
            # Ignore RPyC netref attributes.
            # Also, if stop() is not defined, hasattr() call in our
            # __init__() will bring us here. Don't contact the
            # server in this case either.
            raise AttributeError()
        return getattr(self.server_breakpoint, item)

    def exposed_stop(self):
        # Handle stop() call from the server.
        return self.stop()

class Gdb:
    """Mirror of ``gdb`` module.

    See https://sourceware.org/gdb/onlinedocs/gdb/Basic-Python.html for more
    information.
    """

    def __init__(self, conn):
        """Do not create instances of this class directly.

        Use :func:`attach` or :func:`debug` with ``api=True`` instead.
        """
        self.conn = conn

        class _Breakpoint(Breakpoint):
            def __init__(self, *args, **kwargs):
                super().__init__(conn, *args, **kwargs)

        self.Breakpoint = _Breakpoint
        self.stopped = Event()

        def stop_handler(event):
            self.stopped.set()

        self.events.stop.connect(stop_handler)

    def __getattr__(self, item):
        """Provide access to the attributes of `gdb` module."""
        return getattr(self.conn.root.gdb, item)

    def wait(self):
        """Wait until the program stops."""
        self.stopped.wait()
        self.stopped.clear()

    def interrupt_and_wait(self):
        """Interrupt the program and wait until it stops."""
        self.execute('interrupt')
        self.wait()

    def continue_nowait(self):
        """Continue the program. Do not wait until it stops again."""
        self.execute('continue &')

    def continue_and_wait(self):
        """Continue the program and wait until it stops again."""
        self.continue_nowait()
        self.wait()

    def quit(self):
        """Terminate GDB."""
        self.conn.root.quit()

@LocalContext
def attach(target, gdbscript = '', exe = None, gdb_args = None, ssh = None, sysroot = None, api = False):
    r"""
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
        api(bool): Enable access to GDB Python API.

    Returns:
        PID of the GDB process (or the window which it is running in).
        When ``api=True``, a (PID, :class:`Gdb`) tuple.

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

        Attach to a process by PID

        >>> pid = gdb.attach(1234) # doctest: +SKIP

        Attach to the youngest process by name

        >>> pid = gdb.attach('bash') # doctest: +SKIP

        Attach a debugger to a :class:`.process` tube and automate interaction

        >>> io = process('bash')
        >>> pid = gdb.attach(io, gdbscript='''
        ... call puts("Hello from process debugger!")
        ... detach
        ... quit
        ... ''')
        >>> io.recvline()
        b'Hello from process debugger!\n'
        >>> io.sendline(b'echo Hello from bash && exit')
        >>> io.recvall()
        b'Hello from bash\n'

        Using GDB Python API:

        .. doctest
           :skipif: six.PY2

            >>> io = process('bash')

            Attach a debugger

            >>> pid, io_gdb = gdb.attach(io, api=True)

            Force the program to write something it normally wouldn't

            >>> io_gdb.execute('call puts("Hello from process debugger!")')

            Resume the program

            >>> io_gdb.continue_nowait()

            Observe the forced line

            >>> io.recvline()
            b'Hello from process debugger!\n'

            Interact with the program in a regular way

            >>> io.sendline(b'echo Hello from bash && exit')

            Observe the results

            >>> io.recvall()
            b'Hello from bash\n'

        Attach to the remote process from a :class:`.remote` or :class:`.listen` tube,
        as long as it is running on the same machine.

        >>> server = process(['socat', 'tcp-listen:12345,reuseaddr,fork', 'exec:/bin/bash,nofork'])
        >>> sleep(1) # Wait for socat to start
        >>> io = remote('127.0.0.1', 12345)
        >>> sleep(1) # Wait for process to fork
        >>> pid = gdb.attach(io, gdbscript='''
        ... call puts("Hello from remote debugger!")
        ... detach
        ... quit
        ... ''')
        >>> io.recvline()
        b'Hello from remote debugger!\n'
        >>> io.sendline(b'echo Hello from bash && exit')
        >>> io.recvall()
        b'Hello from bash\n'

        Attach to processes running on a remote machine via an SSH :class:`.ssh` process

        >>> shell = ssh('travis', 'example.pwnme', password='demopass')
        >>> io = shell.process(['cat'])
        >>> pid = gdb.attach(io, gdbscript='''
        ... call sleep(5)
        ... call puts("Hello from ssh debugger!")
        ... detach
        ... quit
        ... ''')
        >>> io.recvline(timeout=5)  # doctest: +SKIP
        b'Hello from ssh debugger!\n'
        >>> io.sendline(b'This will be echoed back')
        >>> io.recvline()
        b'This will be echoed back\n'
        >>> io.close()
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

        if exe and context.os != 'baremetal':
            pre += 'file %s\n' % exe

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

        pids = list(pidof(target))
        if not pids:
            log.error('No such process: %s', target)
        pid = pids[0]
        log.info('Attaching to youngest process "%s" (PID = %d)' %
                 (target, pid))
    elif isinstance(target, tubes.ssh.ssh_channel):
        if not target.pid:
            log.error("PID unknown for channel")

        shell = target.parent

        tmpfile = shell.mktemp()
        gdbscript = b'shell rm %s\n%s' % (tmpfile, packing._need_bytes(gdbscript, 2, 0x80))
        shell.upload_data(gdbscript or b'', tmpfile)

        cmd = ['ssh', '-C', '-t', '-p', str(shell.port), '-l', shell.user, shell.host]
        if shell.password:
            if not misc.which('sshpass'):
                log.error("sshpass must be installed to debug ssh processes")
            cmd = ['sshpass', '-p', shell.password] + cmd
        if shell.keyfile:
            cmd += ['-i', shell.keyfile]
        cmd += ['gdb', '-q', target.executable, target.pid, '-x', tmpfile]

        misc.run_in_new_terminal(cmd)
        return

    elif isinstance(target, tubes.sock.sock):
        pids = proc.pidof(target)
        if not pids:
            log.error('Could not find remote process (%s:%d) on this machine' %
                      target.sock.getpeername())
        pid = pids[0]

        # Specifically check for socat, since it has an intermediary process
        # if you do not specify "nofork" to the EXEC: argument
        # python(2640)───socat(2642)───socat(2643)───bash(2644)
        if proc.exe(pid).endswith('/socat') and time.sleep(0.1) and proc.children(pid):
            pid = proc.children(pid)[0]

        # We may attach to the remote process after the fork but before it performs an exec.  
        # If an exe is provided, wait until the process is actually running the expected exe
        # before we attach the debugger.
        t = Timeout()
        with t.countdown(2):
            while exe and os.path.realpath(proc.exe(pid)) != os.path.realpath(exe) and t.timeout:
                time.sleep(0.1)

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
        log.error("don't know how to attach to target: %r", target)

    # if we have a pid but no exe, just look it up in /proc/
    if pid and not exe:
        exe_fn = proc.exe
        if context.os == 'android':
            exe_fn = adb.proc_exe
        exe = exe_fn(pid)

    if not pid and not exe and not ssh:
        log.error('could not find target process')

    gdb_binary = binary()
    cmd = [gdb_binary]

    if gdb_args:
        cmd += gdb_args

    if context.gdbinit:
        cmd += ['-nh']                  # ignore ~/.gdbinit
        cmd += ['-x', context.gdbinit]  # load custom gdbinit

    cmd += ['-q']

    if exe and context.native:
        if not ssh and not os.path.isfile(exe):
            log.error('No such file: %s', exe)
        cmd += [exe]

    if pid and not context.os == 'android':
        cmd += [str(pid)]

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

    if api:
        # create a UNIX socket for talking to GDB
        socket_dir = tempfile.mkdtemp()
        socket_path = os.path.join(socket_dir, 'socket')
        bridge = os.path.join(os.path.dirname(__file__), 'gdb_api_bridge.py')

        # inject the socket path and the GDB Python API bridge
        pre = 'python socket_path = ' + repr(socket_path) + '\n' + \
              'source ' + bridge + '\n' + \
              pre

    gdbscript = pre + (gdbscript or '')

    if gdbscript:
        tmp = tempfile.NamedTemporaryFile(prefix = 'pwn', suffix = '.gdb',
                                          delete = False, mode = 'w+')
        log.debug('Wrote gdb script to %r\n%s', tmp.name, gdbscript)
        gdbscript = 'shell rm %s\n%s' % (tmp.name, gdbscript)

        tmp.write(gdbscript)
        tmp.close()
        cmd += ['-x', tmp.name]

    log.info('running in new terminal: %s', cmd)

    if api:
        # prevent gdb_faketerminal.py from messing up api doctests
        def preexec_fn():
            os.environ['GDB_FAKETERMINAL'] = '0'
    else:
        preexec_fn = None
    gdb_pid = misc.run_in_new_terminal(cmd, preexec_fn = preexec_fn)

    if pid and context.native:
        proc.wait_for_debugger(pid, gdb_pid)

    if not api:
        return gdb_pid

    # connect to the GDB Python API bridge
    from rpyc import BgServingThread
    from rpyc.utils.factory import unix_connect
    if six.PY2:
        retriable = socket.error
    else:
        retriable = ConnectionRefusedError, FileNotFoundError

    t = Timeout()
    with t.countdown(10):
        while t.timeout:
            try:
                conn = unix_connect(socket_path)
                break
            except retriable:
                time.sleep(0.1)
        else:
            # Check to see if RPyC is installed at all in GDB
            rpyc_check = [gdb_binary, '--nx', '-batch', '-ex',
                          'python import rpyc; import sys; sys.exit(123)']

            if 123 != tubes.process.process(rpyc_check).poll(block=True):
                log.error('Failed to connect to GDB: rpyc is not installed')

            # Check to see if the socket ever got created
            if not os.path.exists(socket_path):
                log.error('Failed to connect to GDB: Unix socket %s was never created', socket_path)

            # Check to see if the remote RPyC client is a compatible version
            version_check = [gdb_binary, '--nx', '-batch', '-ex',
                            'python import platform; print(platform.python_version())']
            gdb_python_version = tubes.process.process(version_check).recvall().strip()
            python_version = str(platform.python_version())

            if gdb_python_version != python_version:
                log.error('Failed to connect to GDB: Version mismatch (%s vs %s)',
                           gdb_python_version,
                           python_version)

            # Don't know what happened
            log.error('Failed to connect to GDB: Unknown error')

    # now that connection is up, remove the socket from the filesystem
    os.unlink(socket_path)
    os.rmdir(socket_dir)

    # create a thread for receiving breakpoint notifications
    BgServingThread(conn, callback=lambda: None)

    return gdb_pid, Gdb(conn)


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
    c.recvuntil(b'port ')
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

    >>> with context.local(log_level=9999):
    ...     shell =  ssh(host='example.pwnme', user='travis', password='demopass')
    ...     bash_libs = gdb.find_module_addresses('/bin/bash', shell)
    >>> os.path.basename(bash_libs[0].path)
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

    #
    # Get the addresses from GDB
    #
    libs = {}
    cmd  = "gdb -q -nh --args %s | cat" % (binary) # pipe through cat to disable colored output on GDB 9+
    expr = re.compile(r'(0x\S+)[^/]+(.*)')

    if ulimit:
        cmd = ['sh', '-c', "(ulimit -s unlimited; %s)" % cmd]
    else:
        cmd = ['sh', '-c', cmd]

    with runner(cmd) as gdb:
        if context.aslr:
            gdb.sendline(b'set disable-randomization off')

        gdb.send(b"""\
        set prompt
        catch load
        run
        """)
        gdb.sendline(b'info sharedlibrary')
        lines = packing._decode(gdb.recvrepeat(2))

        for line in lines.splitlines():
            m = expr.match(line)
            if m:
                libs[m.group(2)] = int(m.group(1),16)
        gdb.sendline(b'kill')
        gdb.sendline(b'y')
        gdb.sendline(b'quit')

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
    r"""Drops a core file for a running local process.

    Note:
        You should use :meth:`.process.corefile` instead of using this method directly.

    Arguments:
        process: Process to dump

    Returns:
        :class:`.Core`: The generated core file

    Example:

        >>> io = process('bash')
        >>> core = gdb.corefile(io)
        >>> core.exe.name # doctest: +ELLIPSIS
        '.../bin/bash'
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
                '-nx',
                '-ex', 'set pagination off',
                '-ex', 'set height 0',
                '-ex', 'set width 0',
                '-ex', 'set use-coredump-filter on',
                '-ex', 'generate-core-file %s' % corefile_path,
                '-ex', 'detach']

    with context.local(terminal = ['sh', '-c']):
        with context.quiet:
            pid = attach(process, gdb_args=gdb_args)
            log.debug("Got GDB pid %d", pid)
            try:
                psutil.Process(pid).wait()
            except psutil.Error:
                pass

    if not os.path.exists(corefile_path):
        log.error("Could not generate a corefile for process %d", process.pid)

    return elf.corefile.Core(corefile_path)

def version(program='gdb'):
    """Gets the current GDB version.

    Note:
        Requires that GDB version meets the following format:

        ``GNU gdb (GDB) 7.12``

    Returns:
        tuple: A tuple containing the version numbers

    Example:

        >>> (7,0) <= gdb.version() <= (12,0)
        True
    """
    program = misc.which(program)
    expr = br'([0-9]+\.?)+'

    with tubes.process.process([program, '--version'], level='error') as gdb:
        version = gdb.recvline()

    versions = re.search(expr, version).group()

    return tuple(map(int, versions.split(b'.')))
