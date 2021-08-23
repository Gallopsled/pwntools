# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division

import ctypes
import errno
import logging
import os
import platform
import select
import signal
import six
import stat
import subprocess
import sys
import time

if sys.platform != 'win32':
    import fcntl
    import pty
    import resource
    import tty

if sys.platform == 'win32':
    import os
    import sys
    import time
    import ctypes
    import random
    import string
    import struct
    import socket
    import logging
    import threading

from pwnlib import qemu
from pwnlib.context import context
from pwnlib.log import getLogger
from pwnlib.timeout import Timeout
from pwnlib.tubes.tube import tube
from pwnlib.util.hashes import sha256file
from pwnlib.util.misc import parse_ldd_output
from pwnlib.util.misc import which
from pwnlib.util.misc import normalize_argv_env
from pwnlib.util.packing import _need_bytes

if sys.platform == 'win32':
    from pwnlib.tubes.os_process.windows_compat import *

log = getLogger(__name__)


class PTY(object): pass


PTY = PTY()
STDOUT = subprocess.STDOUT
PIPE = subprocess.PIPE

signal_names = {-v: k for k, v in signal.__dict__.items() if k.startswith('SIG')}


class process(tube):
    r"""
    Spawns a new process, and wraps it with a tube for communication.
    Arguments:
        argv(list):
            List of arguments to pass to the spawned process.
        shell(bool):
            Set to `True` to interpret `argv` as a string
            to pass to the shell for interpretation instead of as argv.
        executable(str):
            Path to the binary to execute.  If :const:`None`, uses ``argv[0]``.
            Cannot be used with ``shell``.
        cwd(str):
            Working directory.  Uses the current working directory by default.
        env(dict):
            Environment variables.  By default, inherits from Python's environment.
        stdin(int):
            File object or file descriptor number to use for ``stdin``.
            By default, a pipe is used.  A pty can be used instead by setting
            this to ``PTY``.  This will cause programs to behave in an
            interactive manner (e.g.., ``python`` will show a ``>>>`` prompt).
            If the application reads from ``/dev/tty`` directly, use a pty.
        stdout(int):
            File object or file descriptor number to use for ``stdout``.
            By default, a pty is used so that any stdout buffering by libc
            routines is disabled.
            May also be ``PIPE`` to use a normal pipe.
        stderr(int):
            File object or file descriptor number to use for ``stderr``.
            By default, ``STDOUT`` is used.
            May also be ``PIPE`` to use a separate pipe,
            although the :class:`pwnlib.tubes.tube.tube` wrapper will not be able to read this data.
        close_fds(bool):
            Close all open file descriptors except stdin, stdout, stderr.
            By default, :const:`True` is used.
        preexec_fn(callable):
            Callable to invoke immediately before calling ``execve``.
        raw(bool):
            Set the created pty to raw mode (i.e. disable echo and control
            characters).  :const:`True` by default.  If no pty is created, this
            has no effect.
        aslr(bool):
            If set to :const:`False`, disable ASLR via ``personality`` (``setarch -R``)
            and ``setrlimit`` (``ulimit -s unlimited``).
            This disables ASLR for the target process.  However, the ``setarch``
            changes are lost if a ``setuid`` binary is executed.
            The default value is inherited from ``context.aslr``.
            See ``setuid`` below for additional options and information.
        setuid(bool):
            Used to control `setuid` status of the target binary, and the
            corresponding actions taken.
            By default, this value is :const:`None`, so no assumptions are made.
            If :const:`True`, treat the target binary as ``setuid``.
            This modifies the mechanisms used to disable ASLR on the process if
            ``aslr=False``.
            This is useful for debugging locally, when the exploit is a
            ``setuid`` binary.
            If :const:`False`, prevent ``setuid`` bits from taking effect on the
            target binary.  This is only supported on Linux, with kernels v3.5
            or greater.
        where(str):
            Where the process is running, used for logging purposes.
        display(list):
            List of arguments to display, instead of the main executable name.
        alarm(int):
            Set a SIGALRM alarm timeout on the process.
    Examples:
        >>> import sys
        >>> if sys.platform.startswith('win'):
        ...     p = process(b"C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe")
        ...     p.recvuntil(b".")
        ... else:
        ...     b'Windows PowerShell \r\nCopyright (C) Microsoft Corporation.'
        b'Windows PowerShell \r\nCopyright (C) Microsoft Corporation.'

        >>> if sys.platform.startswith('win'):
        ...     p = process(b"C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe")
        ...     _ = p.recvuntil(b"docs> ")
        ...     p.send(b"echo abc")
        ...     p.recvuntil(b'abc')
        ... else:
        ...      b'echo abc'
        b'echo abc'

        >>> if sys.platform.startswith('win'):
        ...     p = process(b"C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe")
        ...     _ = p.recvuntil(b"docs> ")
        ...     p.send(b"echo abc")
        ...     p.recv(25)
        ... else:
        ...      b'echo abc'
        b'echo abc'

        >>> if sys.platform.startswith('win'):
        ...     p = process(b"C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe")
        ...     _ = p.recvuntil(b"docs> ")
        ...     p.write(b"echo abc")
        ...     p.recv(25)
        ... else:
        ...      b'echo abc'
        b'echo abc'

        >>> if sys.platform.startswith('win'):
        ...     pass
        ... else:
        ...     p = process('python2')
        ...     p.sendline(b"print 'Hello world'")
        ...     p.sendline(b"print 'Wow, such data'");

        >>> if sys.platform.startswith('win'):
        ...     True
        ... else:
        ...     p = process('python2')
        ...     p.sendline(b"print 'Hello world'")
        ...     p.sendline(b"print 'Wow, such data'")
        ...     b'' == p.recv(timeout=0.01)
        True

        >>> if sys.platform.startswith('win'):
        ...     True
        ... else:
        ...     p = process('python2')
        ...     p.sendline(b"print 'Hello world'")
        ...     p.sendline(b"print 'Wow, such data'")
        ...     p.shutdown('send')
        ...     p.proc.stdin.closed
        True

        >>> if sys.platform.startswith('win'):
        ...     False
        ... else:
        ...     p = process('python2')
        ...     p.sendline(b"print 'Hello world'")
        ...     p.sendline(b"print 'Wow, such data'")
        ...     p.shutdown('send')
        ...     p.connected('send')
        False
        >>> if sys.platform.startswith('win'):
        ...     b'Hello world\n'
        ... else:
        ...     p = process('python2')
        ...     p.sendline(b"print 'Hello world'")
        ...     p.sendline(b"print 'Wow, such data'")
        ...     p.shutdown('send')
        ...     to_skip = p.connected('send')
        ...     p.recvline()
        b'Hello world\n'
        >>> if sys.platform.startswith('win'):
        ...     b'Wow,'
        ... else:
        ...     p = process('python2')
        ...     p.sendline(b"print 'Hello world'")
        ...     p.sendline(b"print 'Wow, such data'")
        ...     _ = b'' == p.recv(timeout=0.01)
        ...     p.shutdown('send')
        ...     _ = p.proc.stdin.closed
        ...     to_skip = p.connected('send')
        ...     to_skip = p.recvline()
        ...     p.recvuntil(b',')
        b'Wow,'
        >>> if sys.platform.startswith('win'):
        ...     b' such data'
        ... else:
        ...     p = process('python2')
        ...     p.sendline(b"print 'Hello world'")
        ...     p.sendline(b"print 'Wow, such data'")
        ...     _ = b'' == p.recv(timeout=0.01)
        ...     p.shutdown('send')
        ...     _ = p.proc.stdin.closed
        ...     to_skip = p.connected('send')
        ...     to_skip = p.recvline()
        ...     to_skip = p.recvuntil(b',')
        ...     p.recvregex(b'.*data')
        b' such data'
        >>> if sys.platform.startswith('win'):
        ...     b'\n'
        ... else:
        ...     p = process('python2')
        ...     p.sendline(b"print 'Hello world'")
        ...     p.sendline(b"print 'Wow, such data'")
        ...     #b'' == p.recv(timeout=0.01)
        ...     p.shutdown('send')
        ...     #p.proc.stdin.closed
        ...     to_skip = p.connected('send')
        ...     to_skip = p.recvline()
        ...     to_skip = p.recvuntil(b',')
        ...     to_skip = p.recvregex(b'.*data')
        ...     p.recv()
        b'\n'
        >>> if sys.platform.startswith('win'):
        ...     print("Traceback (most recent call last):")
        ...     print("")
        ...     print("EOFError")
        ... else:
        ...     p = process('python2')
        ...     p.sendline(b"print 'Hello world'")
        ...     p.sendline(b"print 'Wow, such data'")
        ...     _ = b'' == p.recv(timeout=0.01)
        ...     p.shutdown('send')
        ...     _ = p.proc.stdin.closed
        ...     to_skip = p.connected('send')
        ...     to_skip = p.recvline()
        ...     to_skip = p.recvuntil(b',')
        ...     to_skip = p.recvregex(b'.*data')
        ...     to_skip = p.recv()
        ...     p.recv() # doctest: +ELLIPSIS
        Traceback (most recent call last):
        ...
        EOFError
        >>> if sys.platform.startswith('win'):
        ...     b''
        ... else:
        ...     p = process('cat')
        ...     d = open('/dev/urandom', 'rb').read(4096)
        ...     p.recv(timeout=0.1)
        b''
        >>> if sys.platform.startswith('win'):
        ...     True
        ... else:
        ...     p = process('cat')
        ...     d = open('/dev/urandom', 'rb').read(4096)
        ...     _ = p.recv(timeout=0.1)
        ...     p.write(d)
        ...     p.recvrepeat(0.1) == d
        True
        >>> if sys.platform.startswith('win'):
        ...     b''
        ... else:
        ...     p = process('cat')
        ...     d = open('/dev/urandom', 'rb').read(4096)
        ...     _ = p.recv(timeout=0.1)
        ...     p.write(d)
        ...     _ = p.recvrepeat(0.1) == d
        ...     p.recv(timeout=0.1)
        b''
        >>> if sys.platform.startswith('win'):
        ...     0
        ... else:
        ...     p = process('cat')
        ...     d = open('/dev/urandom', 'rb').read(4096)
        ...     _ = p.recv(timeout=0.1)
        ...     p.write(d)
        ...     _ = p.recvrepeat(0.1) == d
        ...     _ = p.recv(timeout=0.1)
        ...     p.shutdown('send')
        ...     p.wait_for_close()
        ...     p.poll()
        0
        >>> if sys.platform.startswith('win'):
        ...     b'\x00\x00\x00\x00\x00\x00\x00\x00'
        ... else:
        ...     p = process('cat /dev/zero | head -c8', shell=True, stderr=open('/dev/null', 'w+b'))
        ...     p.recv()
        b'\x00\x00\x00\x00\x00\x00\x00\x00'
        >>> if sys.platform.startswith('win'):
        ...     b'hello\n'
        ... else:
        ...     p = process(['python','-c','import os; print(os.read(2,1024).decode())'],
        ...             preexec_fn = lambda: os.dup2(0,2))
        ...     p.sendline(b'hello')
        ...     p.recvline()
        b'hello\n'
        >>> if sys.platform.startswith('win'):
        ...     b'stack smashing detected'
        ... else:
        ...     stack_smashing = ['python','-c','open("/dev/tty","wb").write(b"stack smashing detected")']
        ...     process(stack_smashing).recvall()
        b'stack smashing detected'
        >>> if sys.platform.startswith('win'):
        ...     b''
        ... else:
        ...     process(stack_smashing, stdout=PIPE).recvall()
        b''
        >>> if sys.platform.startswith('win'):
        ...     b'XXX'
        ... else:
        ...     _ = process(stack_smashing, stdout=PIPE).recvall()
        ...     getpass = ['python','-c','import getpass; print(getpass.getpass("XXX"))']
        ...     p = process(getpass, stdin=PTY)
        ...     p.recv()
        b'XXX'
        >>> if sys.platform.startswith('win'):
        ...     b'\nhunter2\n'
        ... else:
        ...     _ = process(stack_smashing, stdout=PIPE).recvall()
        ...     getpass = ['python','-c','import getpass; print(getpass.getpass("XXX"))']
        ...     p = process(getpass, stdin=PTY)
        ...     _ = p.recv()
        ...     p.sendline(b'hunter2')
        ...     p.recvall()
        b'\nhunter2\n'
        >>> if sys.platform.startswith('win'):
        ...     b'hello\n'
        ... else:
        ...     process('echo hello 1>&2', shell=True).recvall()
        b'hello\n'
        >>> if sys.platform.startswith('win'):
        ...     b''
        ... else:
        ...     process('echo hello 1>&2', shell=True, stderr=PIPE).recvall()
        b''
        >>> if sys.platform.startswith('win'):
        ...     pass
        ... else:
        ...     a = process(['cat', '/proc/self/maps']).recvall()
        >>> if sys.platform.startswith('win'):
        ...     False
        ... else:
        ...     b = process(['cat', '/proc/self/maps'], aslr=False).recvall()
        ...     with context.local(aslr=False):
        ...         c = process(['cat', '/proc/self/maps']).recvall()
        ...     a == b
        False
        >>> if sys.platform.startswith('win'):
        ...     True
        ... else:
        ...     b == c
        True
        >>> if sys.platform.startswith('win'):
        ...     b'unlimited\n'
        ... else:
        ...     process(['sh','-c','ulimit -s'], aslr=0).recvline()
        b'unlimited\n'
        >>> if sys.platform.startswith('win'):
        ...     True
        ... else:
        ...     _ = process(['sh','-c','ulimit -s'], aslr=0).recvline()
        ...     io = process(['sh','-c','sleep 10; exit 7'], alarm=2)
        ...     io.poll(block=True) == -signal.SIGALRM
        True
        >>> if sys.platform.startswith('win'):
        ...     pass
        ... else:
        ...     binary = ELF.from_assembly('nop', arch='mips')
        ...     p = process(binary.path)
        ...     binary_dir, binary_name = os.path.split(binary.path)
        >>> if sys.platform.startswith('win'):
        ...     pass
        ... else:
        ...     p = process('./{}'.format(binary_name), cwd=binary_dir)
        >>> if sys.platform.startswith('win'):
        ...     pass
        ... else:
        ...     p = process(binary.path, cwd=binary_dir)
        >>> if sys.platform.startswith('win'):
        ...     pass
        ... else:
        ...     p = process('./{}'.format(binary_name), cwd=os.path.relpath(binary_dir))
        >>> if sys.platform.startswith('win'):
        ...     pass
        ... else:
        ...      p = process(binary.path, cwd=os.path.relpath(binary_dir))
    """
    if sys.platform.startswith("linux"):
        STDOUT = STDOUT
        PIPE = PIPE
        PTY = PTY

    #: Have we seen the process stop?  If so, this is a unix timestamp.
    _stop_noticed = 0

    def __init__(self, argv=None,
                 shell=False,
                 executable=None,
                 cwd=None,
                 env=None,
                 stdin=PIPE,
                 stdout=PTY,
                 stderr=STDOUT,
                 close_fds=True,
                 preexec_fn=lambda: None,
                 raw=True,
                 aslr=None,
                 setuid=None,
                 where='local',
                 display=None,
                 alarm=None,
                 flags=0x0,
                 nostdhandles=False,
                 *args,
                 **kwargs
                 ):

        if sys.platform.startswith("linux"):
            super(process, self).__init__(*args, **kwargs)

            # Permit using context.binary
            if argv is None:
                if context.binary:
                    argv = [context.binary.path]
                else:
                    raise TypeError('Must provide argv or set context.binary')

            #: :class:`subprocess.Popen` object that backs this process
            self.proc = None

            # We need to keep a copy of the un-_validated environment for printing
            original_env = env

            if shell:
                executable_val, argv_val, env_val = executable, argv, env
            else:
                executable_val, argv_val, env_val = self._validate(cwd, executable, argv, env)

            # Avoid the need to have to deal with the STDOUT magic value.
            if stderr is STDOUT:
                stderr = stdout

            # Determine which descriptors will be attached to a new PTY
            handles = (stdin, stdout, stderr)

            #: Which file descriptor is the controlling TTY
            self.pty = handles.index(PTY) if PTY in handles else None

            #: Whether the controlling TTY is set to raw mode
            self.raw = raw

            #: Whether ASLR should be left on
            self.aslr = aslr if aslr is not None else context.aslr

            #: Whether setuid is permitted
            self._setuid = setuid if setuid is None else bool(setuid)

            # Create the PTY if necessary
            stdin, stdout, stderr, master, slave = self._handles(*handles)

            #: Arguments passed on argv
            self.argv = argv_val

            #: Full path to the executable
            self.executable = executable_val

            #: Environment passed on envp
            self.env = os.environ if env is None else env_val

            if self.executable is None:
                if shell:
                    self.executable = '/bin/sh'
                else:
                    self.executable = which(self.argv[0], path=self.env.get('PATH'))

            self._cwd = os.path.realpath(cwd or os.path.curdir)

            #: Alarm timeout of the process
            self.alarm = alarm

            self.preexec_fn = preexec_fn
            self.display = display or self.program
            self._qemu = False
            self._corefile = None

            message = "Starting %s process %r" % (where, self.display)

            if self.isEnabledFor(logging.DEBUG):
                if argv != [self.executable]: message += ' argv=%r ' % self.argv
                if original_env not in (os.environ, None):  message += ' env=%r ' % self.env

            with self.progress(message) as p:

                if not self.aslr:
                    self.warn_once("ASLR is disabled!")

                # In the event the binary is a foreign architecture,
                # and binfmt is not installed (e.g. when running on
                # Travis CI), re-try with qemu-XXX if we get an
                # 'Exec format error'.
                prefixes = [([], self.executable)]
                exception = None

                for prefix, executable in prefixes:
                    try:
                        args = self.argv
                        if prefix:
                            args = prefix + args
                        self.proc = subprocess.Popen(args=args,
                                                     shell=shell,
                                                     executable=executable,
                                                     cwd=cwd,
                                                     env=self.env,
                                                     stdin=stdin,
                                                     stdout=stdout,
                                                     stderr=stderr,
                                                     close_fds=close_fds,
                                                     preexec_fn=self.__preexec_fn)
                        break
                    except OSError as exception:
                        if exception.errno != errno.ENOEXEC:
                            raise
                        prefixes.append(self.__on_enoexec(exception))

                p.success('pid %i' % self.pid)

            if self.pty is not None:
                if stdin is slave:
                    self.proc.stdin = os.fdopen(os.dup(master), 'r+b', 0)
                if stdout is slave:
                    self.proc.stdout = os.fdopen(os.dup(master), 'r+b', 0)
                if stderr is slave:
                    self.proc.stderr = os.fdopen(os.dup(master), 'r+b', 0)

                os.close(master)
                os.close(slave)

            # Set in non-blocking mode so that a call to call recv(1000) will
            # return as soon as a the first byte is available
            if self.proc.stdout:
                fd = self.proc.stdout.fileno()
                fl = fcntl.fcntl(fd, fcntl.F_GETFL)
                fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)

            # Save off information about whether the binary is setuid / setgid
            self.suid = self.uid = os.getuid()
            self.sgid = self.gid = os.getgid()
            st = os.stat(self.executable)
            if self._setuid:
                if (st.st_mode & stat.S_ISUID):
                    self.suid = st.st_uid
                if (st.st_mode & stat.S_ISGID):
                    self.sgid = st.st_gid

        elif sys.platform.startswith("win"):
            self.cmd = argv
            self.flags = flags
            self.stdhandles = not nostdhandles
            self.debuggerpath = r'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\windbg.exe'
            self.newline = b"\n"
            self.__imports = None
            self.__symbols = None
            self.__libs = None
            self.__offsets = None

            if self.stdhandles:
                self._stdin = Pipe()
                self._stdout = Pipe()
                # stderr mixed with stdout self.stderr = Pipe()
                self.timeout = 500  # ms
                self._default_timeout = 500  # ms

            super(process, self).__init__(*args, **kwargs)

            self._create_process()
            self.proc = [proc for proc in windows.system.processes if proc.name.encode() == self.cmd.split(b"/")[-1]][0]

            if flags != CREATE_SUSPENDED:
                self.wait_initialized()


    def __preexec_fn(self):
        """
        Routine executed in the child process before invoking execve().
        Handles setting the controlling TTY as well as invoking the user-
        supplied preexec_fn.
        """

        if sys.platform.startswith('linux'):
            if self.pty is not None:
                self.__pty_make_controlling_tty(self.pty)

            if not self.aslr:
                try:
                    if context.os == 'linux' and self._setuid is not True:
                        ADDR_NO_RANDOMIZE = 0x0040000
                        ctypes.CDLL('libc.so.6').personality(ADDR_NO_RANDOMIZE)

                    resource.setrlimit(resource.RLIMIT_STACK, (-1, -1))
                except Exception:
                    self.exception("Could not disable ASLR")

            # Assume that the user would prefer to have core dumps.
            try:
                resource.setrlimit(resource.RLIMIT_CORE, (-1, -1))
            except Exception:
                pass

            # Given that we want a core file, assume that we want the whole thing.
            try:
                with open('/proc/self/coredump_filter', 'w') as f:
                    f.write('0xff')
            except Exception:
                pass

            if self._setuid is False:
                try:
                    PR_SET_NO_NEW_PRIVS = 38
                    ctypes.CDLL('libc.so.6').prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
                except Exception:
                    pass

            # Avoid issues with attaching to processes when yama-ptrace is set
            try:
                PR_SET_PTRACER = 0x59616d61
                PR_SET_PTRACER_ANY = -1
                ctypes.CDLL('libc.so.6').prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0)
            except Exception:
                pass

            if self.alarm is not None:
                signal.alarm(self.alarm)

            self.preexec_fn()

        else:
            raise Exception("__preexec_fn implemented only on linux")

    def __on_enoexec(self, exception):
        """We received an 'exec format' error (ENOEXEC)
        This implies that the user tried to execute e.g.
        an ARM binary on a non-ARM system, and does not have
        binfmt helpers installed for QEMU.
        """
        if sys.platform.startswith('linux'):
            # Get the ELF binary for the target executable
            with context.quiet:
                # XXX: Cyclic imports :(
                from pwnlib.elf import ELF
                binary = ELF(self.executable)

            # If we're on macOS, this will never work.  Bail now.
            # if platform.mac_ver()[0]:
            # self.error("Cannot run ELF binaries on macOS")

            # Determine what architecture the binary is, and find the
            # appropriate qemu binary to run it.
            qemu_path = qemu.user_path(arch=binary.arch)

            if not qemu_path:
                raise exception

            qemu_path = which(qemu_path)
            if qemu_path:
                self._qemu = qemu_path

                args = [qemu_path]
                if self.argv:
                    args += ['-0', self.argv[0]]
                args += ['--']

                return [args, qemu_path]

            # If we get here, we couldn't run the binary directly, and
            # we don't have a qemu which can run it.
            self.exception(exception)
        else:
            raise Exception("__on_enoexec implemented only on linux")

    @property
    def program(self):
        """Alias for ``executable``, for backward compatibility.
        Example:
            >>> if sys.platform.startswith('linux'):
            ...     p = process('/bin/true')
            ...     p.executable == '/bin/true'
            ... else:
            ...     True
            True
            >>> if sys.platform.startswith('linux'):
            ...     p.executable == p.program
            ... else:
            ...     True
            True
        """
        if sys.platform.startswith('linux'):
            return self.executable
        else:
            raise Exception("TODO: implement program on windows and more")

    @property
    def cwd(self):
        """Directory that the process is working in.
        Example:
            >>> if sys.platform.startswith('win'):
            ...     True
            ... else:
            ...      p = process('sh')
            ...      p.sendline(b'cd /tmp; echo AAA')
            ...      _ = p.recvuntil(b'AAA')
            ...      p.cwd == '/tmp'
            True
            >>> if sys.platform.startswith('win'):
            ...     '/proc'
            ... else:
            ...      p = process('sh')
            ...      p.sendline(b'cd /tmp; echo AAA')
            ...      _ = p.recvuntil(b'AAA')
            ...      p.sendline(b'cd /proc; echo BBB;')
            ...      _ = p.recvuntil(b'BBB')
            ...      p.cwd
            '/proc'
        """

        try:
            self._cwd = os.readlink('/proc/%i/cwd' % self.pid)
        except Exception:
            pass

        return self._cwd
    def _validate(self, cwd, executable, argv, env):
        """
        Perform extended validation on the executable path, argv, and envp.
        Mostly to make Python happy, but also to prevent common pitfalls.
        """

        if sys.platform.startswith('linux'):
            orig_cwd = cwd
            cwd = cwd or os.path.curdir

            argv, env = normalize_argv_env(argv, env, self, 4)
            if env:
                env = {bytes(k): bytes(v) for k, v in env}
            if argv:
                argv = list(map(bytes, argv))

            #
            # Validate executable
            #
            # - Must be an absolute or relative path to the target executable
            # - If not, attempt to resolve the name in $PATH
            #
            if not executable:
                if not argv:
                    self.error("Must specify argv or executable")
                executable = argv[0]

            if not isinstance(executable, str):
                executable = executable.decode('utf-8')

            path = env and env.get(b'PATH')
            if path:
                path = path.decode()
            else:
                path = os.environ.get('PATH')
            # Do not change absolute paths to binaries
            if executable.startswith(os.path.sep):
                pass

            # If there's no path component, it's in $PATH or relative to the
            # target directory.
            #
            # For example, 'sh'
            elif os.path.sep not in executable and which(executable, path=path):
                executable = which(executable, path=path)

            # Either there is a path component, or the binary is not in $PATH
            # For example, 'foo/bar' or 'bar' with cwd=='foo'
            elif os.path.sep not in executable:
                tmp = executable
                executable = os.path.join(cwd, executable)
                self.warn_once("Could not find executable %r in $PATH, using %r instead" % (tmp, executable))

            # There is a path component and user specified a working directory,
            # it must be relative to that directory. For example, 'bar/baz' with
            # cwd='foo' or './baz' with cwd='foo/bar'
            elif orig_cwd:
                executable = os.path.join(orig_cwd, executable)

            if not os.path.exists(executable):
                self.error("%r does not exist" % executable)
            if not os.path.isfile(executable):
                self.error("%r is not a file" % executable)
            if not os.access(executable, os.X_OK):
                self.error("%r is not marked as executable (+x)" % executable)

            return executable, argv, env
        else:
            raise Exception("_validate not implemented on windows")

    def _handles(self, stdin, stdout, stderr):
        if sys.platform.startswith('linux'):
            master = slave = None

            if self.pty is not None:
                # Normally we could just use PIPE and be happy.
                # Unfortunately, this results in undesired behavior when
                # printf() and similar functions buffer data instead of
                # sending it directly.
                #
                # By opening a PTY for STDOUT, the libc routines will not
                # buffer any data on STDOUT.
                master, slave = pty.openpty()

                if self.raw:
                    # By giving the child process a controlling TTY,
                    # the OS will attempt to interpret terminal control codes
                    # like backspace and Ctrl+C.
                    #
                    # If we don't want this, we set it to raw mode.
                    tty.setraw(master)
                    tty.setraw(slave)

                if stdin is PTY:
                    stdin = slave
                if stdout is PTY:
                    stdout = slave
                if stderr is PTY:
                    stderr = slave

            return stdin, stdout, stderr, master, slave
        else:
            raise Exception("_handles not implemented on windows")

    def __getattr__(self, attr):
        """Permit pass-through access to the underlying process object for
        fields like ``pid`` and ``stdin``.
        """
        if sys.platform.startswith('linux'):
            if hasattr(self.proc, attr):
                return getattr(self.proc, attr)
            raise AttributeError("'process' object has no attribute '%s'" % attr)

        elif sys.platform.startswith('win'):
            pass

    def kill(self):
        """kill()
        Kills the process.
        """
        self.close()

    def poll(self, block=False):
        """poll(block = False) -> int
        Arguments:
            block(bool): Wait for the process to exit
        Poll the exit code of the process. Will return None, if the
        process has not yet finished and the exit code otherwise.
        """

        # In order to facilitate retrieving core files, force an update
        # to the current working directory
        _ = self.cwd

        if block:
            self.wait_for_close()

        if sys.platform.startswith("linux"):
            self.proc.poll()
            returncode = self.proc.returncode
        elif sys.platform.startswith("win"):
            returncode = self.check_closed()

        if returncode is not None and not self._stop_noticed:
            self._stop_noticed = time.time()
            signame = ''
            if returncode < 0:
                signame = ' (%s)' % (signal_names.get(returncode, 'SIG???'))

            self.info("Process %r stopped with exit code %d%s (pid %i)" % (self.display,
                                                                           returncode,
                                                                           signame,
                                                                           self.pid))
        return returncode

    def communicate(self, stdin=None):
        """communicate(stdin = None) -> str
        Calls :meth:`subprocess.Popen.communicate` method on the process.
        """
        if sys.platform.startswith('linux'):
            return self.proc.communicate(stdin)
        else:
            raise Exception("communicate not implemented on windows")

    # Implementation of the methods required for tube
    def recv_raw(self, numb):
        # This is a slight hack. We try to notice if the process is
        # dead, so we can write a message.
        self.poll()

        if sys.platform.startswith("linux"):
            if not self.connected_raw('recv'):
                raise EOFError

        if not self.can_recv_raw(self.timeout):
            return ''

        # This will only be reached if we either have data,
        # or we have reached an EOF. In either case, it
        # should be safe to read without expecting it to block.
        data = b''

        try:
            if sys.platform.startswith("win"):
                if self.stdhandles:
                    data = self.stdout.read(numb)
                self.check_closed()  # but signal it
                data = bytes(data)
            elif sys.platform.startswith("linux"):
                data = self.proc.stdout.read(numb)
        except IOError:
            pass

        if not data:
            self.shutdown("recv")
            raise EOFError

        return data

    def send_raw(self, data):
        if sys.platform.startswith('linux'):
            # This is a slight hack. We try to notice if the process is
            # dead, so we can write a message.
            self.poll()

            if not self.connected_raw('send'):
                raise EOFError

            try:
                self.proc.stdin.write(data)
                self.proc.stdin.flush()
            except IOError:
                raise EOFError
        else:
            raise Exception("send_raw not implemented in windows")

    def settimeout_raw(self, timeout):
        pass

    def can_recv_raw(self, timeout):
        if sys.platform.startswith('linux'):
            if not self.connected_raw('recv'):
                return False

            try:
                if timeout is None:
                    return select.select([self.proc.stdout], [], []) == ([self.proc.stdout], [], [])

                return select.select([self.proc.stdout], [], [], timeout) == ([self.proc.stdout], [], [])
            except ValueError:
                # Not sure why this isn't caught when testing self.proc.stdout.closed,
                # but it's not.
                #
                #   File "/home/user/pwntools/pwnlib/tubes/process.py", line 112, in can_recv_raw
                #     return select.select([self.proc.stdout], [], [], timeout) == ([self.proc.stdout], [], [])
                # ValueError: I/O operation on closed file
                raise EOFError
            except select.error as v:
                if v.args[0] == errno.EINTR:
                    return False
        elif sys.platform.startswith('win'):
            return True#TODO fix it for windows

    def connected_raw(self, direction):
        if sys.platform.startswith('linux'):
            if direction == 'any':
                return self.poll() is None
            elif direction == 'send':
                return not self.proc.stdin.closed
            elif direction == 'recv':
                return not self.proc.stdout.closed
        else:
            raise Exception("not implemented in windows")

    def close(self):
        if sys.platform.startswith('linux'):
            if self.proc is None:
                return

            # First check if we are already dead
            self.poll()

            # close file descriptors
            for fd in [self.proc.stdin, self.proc.stdout, self.proc.stderr]:
                if fd is not None:
                    fd.close()

            if not self._stop_noticed:
                try:
                    self.proc.kill()
                    self.proc.wait()
                    self._stop_noticed = time.time()
                    self.info('Stopped process %r (pid %i)' % (self.program, self.pid))
                except OSError:
                    pass
        elif sys.platform.startswith('win'):
            """close() closes the process"""
            if not self.is_exit:
                self.proc.exit(0)#self.proc.peb.exit(0)
                #self.exit(0)

    def fileno(self):
        if sys.platform.startswith('linux'):
            if not self.connected():
                self.error("A stopped process does not have a file number")
            return self.proc.stdout.fileno()

        elif sys.platform.startswith('win'):
            pass#raise Exception("not implemented on windows")


    def shutdown_raw(self, direction):
        if sys.platform.startswith('linux'):
            if direction == "send":
                self.proc.stdin.close()

            if direction == "recv":
                self.proc.stdout.close()

            if False not in [self.proc.stdin.closed, self.proc.stdout.closed]:
                self.close()
        if sys.platform.startswith('win'):
            raise Exception("not implemented on windows")

    def __pty_make_controlling_tty(self, tty_fd):
        '''This makes the pseudo-terminal the controlling tty. This should be
        more portable than the pty.fork() function. Specifically, this should
        work on Solaris. '''

        if sys.platform.startswith('linux'):
            child_name = os.ttyname(tty_fd)

            # Disconnect from controlling tty. Harmless if not already connected.
            try:
                fd = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY)
                if fd >= 0:
                    os.close(fd)
            # which exception, shouldnt' we catch explicitly .. ?
            except OSError:
                # Already disconnected. This happens if running inside cron.
                pass

            os.setsid()

            # Verify we are disconnected from controlling tty
            # by attempting to open it again.
            try:
                fd = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY)
                if fd >= 0:
                    os.close(fd)
                    raise Exception('Failed to disconnect from '
                                    'controlling tty. It is still possible to open /dev/tty.')
            # which exception, shouldnt' we catch explicitly .. ?
            except OSError:
                # Good! We are disconnected from a controlling tty.
                pass

            # Verify we can open child pty.
            fd = os.open(child_name, os.O_RDWR)
            if fd < 0:
                raise Exception("Could not open child pty, " + child_name)
            else:
                os.close(fd)

            # Verify we now have a controlling tty.
            fd = os.open("/dev/tty", os.O_WRONLY)
            if fd < 0:
                raise Exception("Could not open controlling tty, /dev/tty")
            else:
                os.close(fd)
        elif sys.platform.startswith('win'):
            raise Exception("not implemented on windows")

    def libs(self):
        """libs() -> dict
        Return a dictionary mapping the path of each shared library loaded
        by the process to the address it is loaded at in the process' address
        space.
        """

        if sys.platform.startswith('linux'):
            try:
                maps_raw = open('/proc/%d/maps' % self.pid).read()
            except IOError:
                maps_raw = None

            if not maps_raw:
                import pwnlib.elf.elf

                with context.quiet:
                    return pwnlib.elf.elf.ELF(self.executable).maps

            # Enumerate all of the libraries actually loaded right now.
            maps = {}
            for line in maps_raw.splitlines():
                if '/' not in line: continue
                path = line[line.index('/'):]
                path = os.path.realpath(path)
                if path not in maps:
                    maps[path] = 0

            for lib in maps:
                path = os.path.realpath(lib)
                for line in maps_raw.splitlines():
                    if line.endswith(path):
                        address = line.split('-')[0]
                        maps[lib] = int(address, 16)
                        break

            return maps
        elif sys.platform.startswith('win'):
            """libs returns a dict of loaded modules with their baseaddr like {'ntdll.dll': 0x123456000, ...}"""
            if not self.check_initialized():
                return {}
            if not self.__libs:
                self.__libs = {module.name.lower(): module.baseaddr for module in self.proc.peb.modules if module.name}
            return self.__libs

    @property
    def libc(self):
        """libc() -> ELF
        Returns an ELF for the libc for the current process.
        If possible, it is adjusted to the correct address
        automatically.
        Example:
        >>> if sys.platform.startswith('linux'):
        ...     p = process("/bin/cat")
        ...     libc = p.libc
        ...     libc.path
        ... else:
        ...     '/lib64/libc-...so'
        '/lib64/libc-...so'
        >>> if sys.platform.startswith('linux'):
        ...     p.close()
        ... else:
        ...     pass
        """
        if sys.platform.startswith('linux'):
            from pwnlib.elf import ELF

            for lib, address in self.libs().items():
                if 'libc.so' in lib or 'libc-' in lib:
                    e = ELF(lib)
                    e.address = address
                    return e
        elif sys.platform.startswith('win'):
            raise Exception("There is no libc on windows.")

    @property
    def elf(self):
        """elf() -> pwnlib.elf.elf.ELF
        Returns an ELF file for the executable that launched the process.
        """
        if sys.platform.startswith('linux'):
            import pwnlib.elf.elf
            return pwnlib.elf.elf.ELF(self.executable)
        elif sys.platform.startswith('win'):
            raise Exception("There is no ELF on windows")

    @property
    def corefile(self):
        """corefile() -> pwnlib.elf.elf.Core
        Returns a corefile for the process.
        If the process is alive, attempts to create a coredump with GDB.
        If the process is dead, attempts to locate the coredump created
        by the kernel.
        """
        # If the process is still alive, try using GDB
        import pwnlib.elf.corefile

        if sys.platform.startswith('linux'):
            import pwnlib.gdb

            try:
                if self.poll() is None:
                    corefile = pwnlib.gdb.corefile(self)
                    if corefile is None:
                        self.error("Could not create corefile with GDB for %s", self.executable)
                    return corefile

                # Handle race condition against the kernel or QEMU to write the corefile
                # by waiting up to 5 seconds for it to be written.
                t = Timeout()
                finder = None
                with t.countdown(5):
                    while t.timeout and (finder is None or not finder.core_path):
                        finder = pwnlib.elf.corefile.CorefileFinder(self)
                        time.sleep(0.5)

                if not finder.core_path:
                    self.error("Could not find core file for pid %i" % self.pid)

                core_hash = sha256file(finder.core_path)

                if self._corefile and self._corefile._hash == core_hash:
                    return self._corefile

                self._corefile = pwnlib.elf.corefile.Corefile(finder.core_path)
            except AttributeError as e:
                raise RuntimeError(e)  # AttributeError would route through __getattr__, losing original message
            self._corefile._hash = core_hash

            return self._corefile
        elif sys.platform.startswith('win'):
            raise Exception("There is no corefile on windows")

    def leak(self, address, count=1):
        r"""Leaks memory within the process at the specified address.
        Arguments:
            address(int): Address to leak memory at
            count(int): Number of bytes to leak at that address.
        Example:
            >>> if sys.platform.startswith("linux"):
            ...     e = ELF(which('bash-static'))
            ...     p = process(e.path)

            In order to make sure there's not a race condition against
            the process getting set up...

            >>> if sys.platform.startswith("linux"):
            ...     p.sendline(b'echo hello')
            ...     p.recvuntil(b'hello')
            ... else:
            ...     b'hello'
            b'hello'

            Now we can leak some data!
            >>> if sys.platform.startswith("linux"):
            ...     p.leak(e.address, 4)
            ... else:
            ...     b'\x7fELF'
            b'\x7fELF'
        """

        if sys.platform.startswith('linux'):
            # If it's running under qemu-user, don't leak anything.
            if 'qemu-' in os.path.realpath('/proc/%i/exe' % self.pid):
                self.error("Cannot use leaker on binaries under QEMU.")

            with open('/proc/%i/mem' % self.pid, 'rb') as mem:
                mem.seek(address)
                return mem.read(count) or None

            readmem = leak
        elif sys.platform.startswith('win'):
            raise Exception("not implemented on windows")

    def writemem(self, address, data):
        r"""Writes memory within the process at the specified address.
        Arguments:
            address(int): Address to write memory
            data(bytes): Data to write to the address
        Example:

            Let's write data to  the beginning of the mapped memory of the  ELF.
            >>> if sys.platform.startswith("linux"):
            ...     context.clear(arch='i386')
            ...     address = 0x100000
            ...     data = cyclic(32)
            ...     assembly = shellcraft.nop() * len(data)

            Wait for one byte of input, then write the data to stdout
            >>> if sys.platform.startswith("linux"):
            ...     assembly += shellcraft.write(1, address, 1)
            ...     assembly += shellcraft.read(0, 'esp', 1)
            ...     assembly += shellcraft.write(1, address, 32)
            ...     assembly += shellcraft.exit()
            ...     asm(assembly)[32:]
            ... else:
            ...     b'j\x01[\xb9\xff\xff\xef\xff\xf7\xd1\x89\xdaj\x04X\xcd\x801\xdb\x89\xe1j\x01Zj\x03X\xcd\x80j\x01[\xb9\xff\xff\xef\xff\xf7\xd1j Zj\x04X\xcd\x801\xdbj\x01X\xcd\x80'
            b'j\x01[\xb9\xff\xff\xef\xff\xf7\xd1\x89\xdaj\x04X\xcd\x801\xdb\x89\xe1j\x01Zj\x03X\xcd\x80j\x01[\xb9\xff\xff\xef\xff\xf7\xd1j Zj\x04X\xcd\x801\xdbj\x01X\xcd\x80'

            Assemble the binary and test it
            >>> if sys.platform.startswith("linux"):
            ...     elf = ELF.from_assembly(assembly, vma=address)
            ...     io = elf.process()
            ...     _ = io.recvuntil(b'\x90')
            ...     _ = io.writemem(address, data)
            ...     io.send(b'X')
            ...     io.recvall()
            ... else:
            ...     b'aaaabaaacaaadaaaeaaafaaagaaahaaa'
            b'aaaabaaacaaadaaaeaaafaaagaaahaaa'
        """

        if sys.platform.startswith('linux'):
            if 'qemu-' in os.path.realpath('/proc/%i/exe' % self.pid):
                self.error("Cannot use leaker on binaries under QEMU.")

            with open('/proc/%i/mem' % self.pid, 'wb') as mem:
                mem.seek(address)
                return mem.write(data)
        elif sys.platform.startswith('win'):
            raise Exception("writemem not implemented on windows")

    @property
    def stdin(self):
        """Shorthand for ``self.proc.stdin``
        See: :obj:`.process.proc`
        """
        if sys.platform.startswith('linux'):
            return self.proc.stdin
        elif sys.platform.startswith('win'):
            return self._stdin

    @property
    def stdout(self):
        """Shorthand for ``self.proc.stdout``
        See: :obj:`.process.proc`
        """
        if sys.platform.startswith('linux'):
            return self.proc.stdout
        elif sys.platform.startswith('win'):
            return self._stdout

    @property
    def stderr(self):
        """Shorthand for ``self.proc.stderr``
        See: :obj:`.process.proc`
        """
        if sys.platform.startswith('linux'):
            return self.proc.stderr
        elif sys.platform.startswith('win'):
            raise Exception("not implemented yet")

    def check_initialized(self):
        if sys.platform.startswith('linux'):
            Exception("avaible only on windows")
        elif sys.platform.startswith('win'):
            is_init = False
            try:  # Accessing PEB
                self.proc.peb.modules[1]
                is_init = True
            except Exception as e:
                logging.info(e)
                pass
            if not is_init:
                logging.info("Process {0} not initialized ...".format(self))
            return is_init

    def wait_initialized(self):
        if sys.platform.startswith('linux'):
            raise Exception("avaible only on windows")
        elif sys.platform.startswith('win'):
            while not self.check_initialized():
                #print(GetLastError())
                time.sleep(0.50)

    def __del__(self):
        if sys.platform.startswith("linux"):
            pass
        elif sys.platform.startswith("win"):
            if self.pid and self is not None:
                self.proc.exit(0)


    def _create_process(self):
        if sys.platform.startswith('linux'):
            raise Exception("avaible only on windows")
        elif sys.platform.startswith('win'):
            proc_info = PROCESS_INFORMATION()
            lpStartupInfo = None
            StartupInfo = STARTUPINFOA()
            StartupInfo.cb = ctypes.sizeof(StartupInfo)
            if self.stdhandles:
                StartupInfo.dwFlags = gdef.STARTF_USESTDHANDLES
                StartupInfo.hStdInput = self.stdin.get_handle('r')
                StartupInfo.hStdOutput = self.stdout.get_handle('w')
                StartupInfo.hStdError = self.stdout.get_handle('w')
            lpStartupInfo = ctypes.byref(StartupInfo)
            lpCommandLine = None
            lpApplicationName = self.cmd

            if isinstance(self.cmd, (list,)):
                lpCommandLine = (b" ".join([bytes(a) for a in self.cmd]))
                lpApplicationName = None
            try:
                windows.winproxy.CreateProcessA(lpApplicationName, lpCommandLine=lpCommandLine, bInheritHandles=True,
                                                dwCreationFlags=self.flags,
                                                lpProcessInformation=ctypes.byref(proc_info),
                                                lpStartupInfo=lpStartupInfo)
                windows.winproxy.CloseHandle(proc_info.hThread)
                self.pid = proc_info.dwProcessId
                self.phandle = proc_info.hProcess
            except Exception as exception:
                self.__pid = None
                self.__phandle = None
                raise("Exception {0}: Process {1} failed to start!".format(exception, self.cmd))

    def check_exit(self, raise_exc=False):
        if sys.platform.startswith('linux'):
            raise Exception("avaible only on windows")
        elif sys.platform.startswith('win'):
            if self.is_exit:
                if raise_exc:
                    raise (EOFError("Process {0} exited".format(self)))
                else:
                    logging.warning("EOFError: Process {0} exited".format(self))
                    return None

    def check_closed(self, raise_exc=False):
        if sys.platform.startswith('linux'):
            raise Exception("avaible only on windows")
        elif sys.platform.startswith('win'):
            if self.stdhandles and self.client_count() < 2:
                if raise_exc:
                    raise (EOFError("Process {:s} I/O is closed".format(self)))
                else:
                    logging.warning("EOFError: Process {0} I/O is closed".format(self))
                return True
            elif self.stdhandles:
                return False
            else:
                return self.check_exit(raise_exc)

    def client_count(self):
        if sys.platform.startswith('linux'):
            raise Exception("avaible only on windows")
        elif sys.platform.startswith('win'):
            if not self.stdhandles:
                logging.error("client_count called on process {:s} with no input forwarding".format(self))
                return 0
            return max(self.stdin.number_of_clients(), self._stdout.number_of_clients())

    def get_timeout(self):
        if sys.platform.startswith('linux'):
            raise Exception("avaible only on windows")
        elif sys.platform.startswith('win'):
            if self.stdhandles:
                return self._timeout
            return -1

    def set_timeout(self, timeout):
        if sys.platform.startswith('linux'):
            raise Exception("avaible only on windows")
        elif sys.platform.startswith('win'):
            if timeout:
                self._timeout = timeout
                if self.stdhandles:
                    self._stdin.timeout = timeout
                    self._stdout.timeout = timeout
            elif self._timeout != self._default_timeout:
                self.timeout = self._default_timeout

    if sys.platform.startswith('win'):
        timeout = property(get_timeout, set_timeout)
    """timeout in ms for read on the process stdout (pipe)"""
