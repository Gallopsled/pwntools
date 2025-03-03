# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division

import ctypes
import errno
import logging
import os
import select
import signal
import stat
import subprocess
import sys
import time
from collections import namedtuple

IS_WINDOWS = sys.platform.startswith('win')

if IS_WINDOWS:
    import queue
    import threading
else:
    import fcntl
    import pty
    import resource
    import tty

from pwnlib import qemu
from pwnlib.context import context
from pwnlib.log import getLogger
from pwnlib.timeout import Timeout
from pwnlib.tubes.tube import tube
from pwnlib.util.hashes import sha256file
from pwnlib.util.misc import parse_ldd_output
from pwnlib.util.misc import which
from pwnlib.util.misc import normalize_argv_env
from pwnlib.util.packing import _decode

log = getLogger(__name__)

class PTY(object): pass
PTY=PTY()
STDOUT = subprocess.STDOUT
PIPE = subprocess.PIPE

signal_names = {-v:k for k,v in signal.__dict__.items() if k.startswith('SIG')}

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
            Environment variables to add to the environment.
        ignore_environ(bool):
            Ignore Python's environment.  By default use Python's environment iff env not specified.
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
        creationflags(int):
            Windows only.  Flags to pass to ``CreateProcess``.

    Examples:

        >>> p = process('python')
        >>> p.sendline(b"print('Hello world')")
        >>> p.sendline(b"print('Wow, such data')")
        >>> b'' == p.recv(timeout=0.01)
        True
        >>> p.shutdown('send')
        >>> p.proc.stdin.closed
        True
        >>> p.connected('send')
        False
        >>> p.recvline()
        b'Hello world\n'
        >>> p.recvuntil(b',')
        b'Wow,'
        >>> p.recvregex(b'.*data')
        b' such data'
        >>> p.recv()
        b'\n'
        >>> p.recv() # doctest: +ELLIPSIS
        Traceback (most recent call last):
        ...
        EOFError

        >>> p = process('cat')
        >>> d = open('/dev/urandom', 'rb').read(4096)
        >>> p.recv(timeout=0.1)
        b''
        >>> p.write(d)
        >>> p.recvrepeat(0.1) == d
        True
        >>> p.recv(timeout=0.1)
        b''
        >>> p.shutdown('send')
        >>> p.wait_for_close()
        >>> p.poll()
        0

        >>> p = process('cat /dev/zero | head -c8', shell=True, stderr=open('/dev/null', 'w+b'))
        >>> p.recv()
        b'\x00\x00\x00\x00\x00\x00\x00\x00'

        >>> p = process(['python','-c','import os; print(os.read(2,1024).decode())'],
        ...             preexec_fn = lambda: os.dup2(0,2))
        >>> p.sendline(b'hello')
        >>> p.recvline()
        b'hello\n'

        >>> stack_smashing = ['python','-c','open("/dev/tty","wb").write(b"stack smashing detected")']
        >>> process(stack_smashing).recvall()
        b'stack smashing detected'

        >>> process(stack_smashing, stdout=PIPE).recvall()
        b''

        >>> getpass = ['python','-c','import getpass; print(getpass.getpass("XXX"))']
        >>> p = process(getpass, stdin=PTY)
        >>> p.recv()
        b'XXX'
        >>> p.sendline(b'hunter2')
        >>> p.recvall()
        b'\nhunter2\n'

        >>> process('echo hello 1>&2', shell=True).recvall()
        b'hello\n'

        >>> process('echo hello 1>&2', shell=True, stderr=PIPE).recvall()
        b''

        >>> a = process(['cat', '/proc/self/maps']).recvall()
        >>> b = process(['cat', '/proc/self/maps'], aslr=False).recvall()
        >>> with context.local(aslr=False):
        ...    c = process(['cat', '/proc/self/maps']).recvall()
        >>> a == b
        False
        >>> b == c
        True

        >>> process(['sh','-c','ulimit -s'], aslr=0).recvline()
        b'unlimited\n'

        >>> io = process(['sh','-c','sleep 10; exit 7'], alarm=2)
        >>> io.poll(block=True) == -signal.SIGALRM
        True

        >>> binary = ELF.from_assembly('nop', arch='mips')
        >>> p = process(binary.path)
        >>> binary_dir, binary_name = os.path.split(binary.path)
        >>> p = process('./{}'.format(binary_name), cwd=binary_dir)
        >>> p = process(binary.path, cwd=binary_dir)
        >>> p = process('./{}'.format(binary_name), cwd=os.path.relpath(binary_dir))
        >>> p = process(binary.path, cwd=os.path.relpath(binary_dir))
    """

    STDOUT = STDOUT
    PIPE = PIPE
    PTY = PTY

    #: Have we seen the process stop?  If so, this is a unix timestamp.
    _stop_noticed = 0

    proc = None

    def __init__(self, argv = None,
                 shell = False,
                 executable = None,
                 cwd = None,
                 env = None,
                 ignore_environ = None,
                 stdin  = PIPE,
                 stdout = PTY if not IS_WINDOWS else PIPE,
                 stderr = STDOUT,
                 close_fds = True,
                 preexec_fn = lambda: None,
                 raw = True,
                 aslr = None,
                 setuid = None,
                 where = 'local',
                 display = None,
                 alarm = None,
                 creationflags = 0,
                 *args,
                 **kwargs
                 ):
        super(process, self).__init__(*args,**kwargs)

        # Permit using context.binary
        if argv is None:
            if context.binary:
                argv = [context.binary.path]
            else:
                raise TypeError('Must provide argv or set context.binary')

        if IS_WINDOWS and PTY in (stdin, stdout, stderr):
            raise NotImplementedError("ConPTY isn't implemented yet")

        #: :class:`subprocess.Popen` object that backs this process
        self.proc = None

        # We need to keep a copy of the un-_validated environment for printing
        original_env = env

        if shell:
            executable_val, argv_val, env_val = executable, argv, env
            if executable is None:
                if IS_WINDOWS:
                    executable_val = os.environ.get('ComSpec', 'cmd.exe')
                else:
                    executable_val = '/bin/sh'
        else:
            executable_val, argv_val, env_val = self._validate(cwd, executable, argv, env)

        # Avoid the need to have to deal with the STDOUT magic value.
        if stderr is STDOUT:
            stderr = stdout

        if IS_WINDOWS:
            self.pty = None
            self.raw = False
            self.aslr = True
            self._setuid = False
            self.suid = self.uid = None
            self.sgid = self.gid = None
            internal_preexec_fn = None
        else:
            # Determine which descriptors will be attached to a new PTY
            handles = (stdin, stdout, stderr)

            #: Which file descriptor is the controlling TTY
            self.pty          = handles.index(PTY) if PTY in handles else None

            #: Whether the controlling TTY is set to raw mode
            self.raw          = raw

            #: Whether ASLR should be left on
            self.aslr         = aslr if aslr is not None else context.aslr

            #: Whether setuid is permitted
            self._setuid      = setuid if setuid is None else bool(setuid)

            # Create the PTY if necessary
            stdin, stdout, stderr, master, slave = self._handles(*handles)

            internal_preexec_fn = self.__preexec_fn

        #: Arguments passed on argv
        self.argv = argv_val

        #: Full path to the executable
        self.executable = executable_val

        if ignore_environ is None:
            ignore_environ = env is not None  # compat

        #: Environment passed on envp
        self.env = {} if ignore_environ else dict(getattr(os, "environb", os.environ))

        # Add environment variables as needed
        self.env.update(env_val or {})

        self._cwd = os.path.realpath(cwd or os.path.curdir)

        #: Alarm timeout of the process
        self.alarm        = alarm

        self.preexec_fn = preexec_fn
        self.display    = display or self.program
        self._qemu      = False
        self._corefile  = None

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
                    self.proc = subprocess.Popen(args = args,
                                                 shell = shell,
                                                 executable = executable,
                                                 cwd = cwd,
                                                 env = self.env,
                                                 stdin = stdin,
                                                 stdout = stdout,
                                                 stderr = stderr,
                                                 close_fds = close_fds,
                                                 preexec_fn = internal_preexec_fn,
                                                 creationflags = creationflags)
                    break
                except OSError as exception:
                    if exception.errno != errno.ENOEXEC:
                        raise
                    prefixes.append(self.__on_enoexec(exception))

            p.success('pid %i' % self.pid)

        if IS_WINDOWS:
            self._read_thread = None
            self._read_queue = queue.Queue()
            if self.proc.stdout:
                # Read from stdout in a thread
                self._read_thread = threading.Thread(target=_read_in_thread, args=(self._read_queue, self.proc.stdout))
                self._read_thread.daemon = True
                self._read_thread.start()
            return

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

    def __preexec_fn(self):
        """
        Routine executed in the child process before invoking execve().

        Handles setting the controlling TTY as well as invoking the user-
        supplied preexec_fn.
        """
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

    def __on_enoexec(self, exception):
        """We received an 'exec format' error (ENOEXEC)

        This implies that the user tried to execute e.g.
        an ARM binary on a non-ARM system, and does not have
        binfmt helpers installed for QEMU.
        """
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

    @property
    def program(self):
        """Alias for ``executable``, for backward compatibility.

        Example:

            >>> p = process('/bin/true')
            >>> p.executable == '/bin/true'
            True
            >>> p.executable == p.program
            True

        """
        return self.executable

    @property
    def cwd(self):
        """Directory that the process is working in.

        Example:

            >>> p = process('sh')
            >>> p.sendline(b'cd /tmp; echo AAA')
            >>> _ = p.recvuntil(b'AAA')
            >>> p.cwd == '/tmp'
            True
            >>> p.sendline(b'cd /proc; echo BBB;')
            >>> _ = p.recvuntil(b'BBB')
            >>> p.cwd
            '/proc'
        """
        try:
            from pwnlib.util.proc import cwd
            self._cwd = cwd(self.pid)
        except Exception:
            pass

        return self._cwd


    def _validate(self, cwd, executable, argv, env):
        """
        Perform extended validation on the executable path, argv, and envp.

        Mostly to make Python happy, but also to prevent common pitfalls.
        """

        orig_cwd = cwd
        cwd = cwd or os.path.curdir

        argv, env = normalize_argv_env(argv, env, self, 4)
        if env:
            if sys.platform == 'win32':
                # Windows requires that all environment variables be strings
                env = {_decode(k): _decode(v) for k, v in env}
            else:
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
            self.error("%r does not exist"  % executable)
        if not os.path.isfile(executable):
            self.error("%r is not a file" % executable)
        if not os.access(executable, os.X_OK):
            self.error("%r is not marked as executable (+x)" % executable)

        return executable, argv, env

    def _handles(self, stdin, stdout, stderr):
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

    def __getattr__(self, attr):
        """Permit pass-through access to the underlying process object for
        fields like ``pid`` and ``stdin``.
        """
        if not attr.startswith('_') and hasattr(self.proc, attr):
            return getattr(self.proc, attr)
        raise AttributeError("'process' object has no attribute '%s'" % attr)

    def kill(self):
        """kill()

        Kills the process.
        """
        self.close()

    def poll(self, block = False):
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

        self.proc.poll()
        returncode = self.proc.returncode

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

    def communicate(self, stdin = None):
        """communicate(stdin = None) -> str

        Calls :meth:`subprocess.Popen.communicate` method on the process.
        """

        return self.proc.communicate(stdin)

    # Implementation of the methods required for tube
    def recv_raw(self, numb):
        # This is a slight hack. We try to notice if the process is
        # dead, so we can write a message.
        self.poll()

        if not self.connected_raw('recv'):
            raise EOFError

        if not self.can_recv_raw(self.timeout):
            return ''

        if IS_WINDOWS:
            data = b''
            count = 0
            while count < numb:
                if self._read_queue.empty():
                    break
                last_byte = self._read_queue.get(block=False)
                data += last_byte
                count += 1
            return data

        # This will only be reached if we either have data,
        # or we have reached an EOF. In either case, it
        # should be safe to read without expecting it to block.
        data = ''

        try:
            data = self.proc.stdout.read(numb)
        except IOError:
            pass

        if not data:
            self.shutdown("recv")
            raise EOFError

        return data

    def send_raw(self, data):
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

    def settimeout_raw(self, timeout):
        pass

    def can_recv_raw(self, timeout):
        if not self.connected_raw('recv'):
            return False

        if IS_WINDOWS:
            with self.countdown(timeout=timeout):
                while self.timeout and self._read_queue.empty():
                    time.sleep(0.01)
                return not self._read_queue.empty()

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

    def connected_raw(self, direction):
        if direction == 'any':
            return self.poll() is None
        elif direction == 'send':
            return self.proc.stdin and not self.proc.stdin.closed
        elif direction == 'recv':
            return self.proc.stdout and not self.proc.stdout.closed

    def close(self):
        if self.proc is None:
            return

        # First check if we are already dead
        self.poll()

        if not self._stop_noticed:
            try:
                self.proc.kill()
                self.proc.wait()
                self._stop_noticed = time.time()
                self.info('Stopped process %r (pid %i)' % (self.program, self.pid))
            except OSError:
                pass

        # close file descriptors
        for fd in [self.proc.stdin, self.proc.stdout, self.proc.stderr]:
            if fd is not None:
                try:
                    fd.close()
                except IOError as e:
                    if e.errno != errno.EPIPE and e.errno != errno.EINVAL:
                        raise


    def fileno(self):
        if not self.connected():
            self.error("A stopped process does not have a file number")

        return self.proc.stdout.fileno()

    def shutdown_raw(self, direction):
        if direction == "send":
            self.proc.stdin.close()

        if direction == "recv":
            self.proc.stdout.close()

        if all(fp is None or fp.closed for fp in [self.proc.stdin, self.proc.stdout]):
            self.close()

    def __pty_make_controlling_tty(self, tty_fd):
        '''This makes the pseudo-terminal the controlling tty. This should be
        more portable than the pty.fork() function. Specifically, this should
        work on Solaris. '''

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

    def maps(self):
        """maps() -> [mapping]

        Returns a list of process mappings.
        A mapping object has the following fields:
            addr, address (addr alias), start (addr alias), end, size, perms, path, rss, pss, shared_clean, shared_dirty, private_clean, private_dirty, referenced, anonymous, swap
        perms is a permissions object, with the following fields:
            read, write, execute, private, shared, string

        Example:
      
            >>> p = process(['cat'])
            >>> p.sendline(b"meow")
            >>> p.recvline()
            b'meow\\n'
            >>> proc_maps = open("/proc/" + str(p.pid) + "/maps", "r").readlines()
            >>> pwn_maps = p.maps()
            >>> len(proc_maps) == len(pwn_maps)
            True
            >>> checker_arr = []
            >>> for proc, pwn in zip(proc_maps, pwn_maps):
            ...     proc = proc.split(' ')
            ...     p_addrs = proc[0].split('-')
            ...     checker_arr.append(int(p_addrs[0], 16) == pwn.addr == pwn.address == pwn.start)
            ...     checker_arr.append(int(p_addrs[1], 16) == pwn.end)
            ...     checker_arr.append(pwn.size == pwn.end - pwn.start)
            ...     checker_arr.append(pwn.perms.string == proc[1])
            ...     proc_path = proc[-1].strip()
            ...     checker_arr.append(pwn.path == proc_path or (pwn.path == '[anon]' and proc_path == ''))
            ...
            >>> checker_arr == [True] * len(proc_maps) * 5
            True

        """

        """
        Useful information about this can be found at: https://man7.org/linux/man-pages/man5/proc.5.html
        specifically the /proc/pid/maps section.

        memory_maps() returns a list of pmmap_ext objects

        The definition (from psutil/_pslinux.py) is:
        pmmap_grouped = namedtuple(
            'pmmap_grouped',
            ['path', 'rss', 'size', 'pss', 'shared_clean', 'shared_dirty',
            'private_clean', 'private_dirty', 'referenced', 'anonymous', 'swap'])
        pmmap_ext = namedtuple(
            'pmmap_ext', 'addr perms ' + ' '.join(pmmap_grouped._fields))

            
        Here is an example of a pmmap_ext entry: 
            pmmap_ext(addr='15555551c000-155555520000', perms='r--p', path='[vvar]', rss=0, size=16384, pss=0, shared_clean=0, shared_dirty=0, private_clean=0, private_dirty=0, referenced=0, anonymous=0, swap=0)
        """

        permissions = namedtuple("permissions", "read write execute private shared string")
        mapping = namedtuple("mapping", 
            "addr address start end size perms path rss pss shared_clean shared_dirty private_clean private_dirty referenced anonymous swap")
        # addr = address (alias) = start (alias)

        from pwnlib.util.proc import memory_maps
        raw_maps = memory_maps(self.pid)

        maps = []
        # raw_mapping
        for r_m in raw_maps:
            p_perms = permissions('r' in r_m.perms, 'w' in r_m.perms, 'x' in r_m.perms, 'p' in r_m.perms, 's' in r_m.perms, r_m.perms)
            addr_split = r_m.addr.split('-')
            p_addr = int(addr_split[0], 16)
            p_mapping = mapping(p_addr, p_addr, p_addr, int(addr_split[1], 16), r_m.size, p_perms, r_m.path, r_m.rss,
                                r_m.pss, r_m.shared_clean, r_m.shared_dirty, r_m.private_clean, r_m.private_dirty,
                                r_m.referenced, r_m.anonymous, r_m.swap)
            maps.append(p_mapping)

        return maps

    def get_mapping(self, path_value, single=True):
        """get_mapping(path_value, single=True) -> mapping
        get_mapping(path_value, False) -> [mapping]

        Arguments:
            path_value(str): The exact path of the requested mapping,
                valid values are also [stack], [heap], etc..
            single(bool=True): Whether to only return the first
                mapping matched, or all of them.

        Returns found mapping(s) in process memory according to 
        path_value.

        Example:
            
            >>> p = process(['cat'])
            >>> mapping = p.get_mapping('[stack]')
            >>> mapping.path == '[stack]'
            True
            >>> mapping.perms.execute
            False
            >>>
            >>> mapping = p.get_mapping('does not exist')
            >>> print(mapping)
            None
            >>>
            >>> mappings = p.get_mapping(which('cat'), single=False)
            >>> len(mappings) > 1
            True

        """
        all_maps = self.maps()

        if single:
            for mapping in all_maps:
                if path_value == mapping.path:
                    return mapping
            return None

        m_mappings = []
        for mapping in all_maps:
            if path_value == mapping.path:
                m_mappings.append(mapping)
        return m_mappings

    def stack_mapping(self, single=True):
        """stack_mapping(single=True) -> mapping
        stack_mapping(False) -> [mapping]

        Arguments:
            single(bool=True): Whether to only return the first
                mapping matched, or all of them.

        Returns :meth:`.process.get_mapping` with '[stack]' and single as arguments.

        Example:

            >>> p = process(['cat'])
            >>> mapping = p.stack_mapping()
            >>> mapping.path
            '[stack]'
            >>> mapping.perms.execute
            False
            >>> mapping.perms.write
            True
            >>> hex(mapping.address) # doctest: +SKIP
            '0x7fffd99fe000'
            >>> mappings = p.stack_mapping(single=False)
            >>> len(mappings)
            1

        """
        return self.get_mapping('[stack]', single)
    
    def heap_mapping(self, single=True):
        """heap_mapping(single=True) -> mapping
        heap_mapping(False) -> [mapping]

        Arguments:
            single(bool=True): Whether to only return the first
                mapping matched, or all of them.

        Returns :meth:`.process.get_mapping` with '[heap]' and single as arguments.

        Example:

            >>> p = process(['cat'])
            >>> p.sendline(b'meow')
            >>> p.recvline()
            b'meow\\n'
            >>> mapping = p.heap_mapping()
            >>> mapping.path
            '[heap]'
            >>> mapping.perms.execute
            False
            >>> mapping.perms.write
            True
            >>> hex(mapping.address) # doctest: +SKIP
            '0x557650fae000'
            >>> mappings = p.heap_mapping(single=False)
            >>> len(mappings)
            1

        """
        return self.get_mapping('[heap]', single)
    
    def vdso_mapping(self, single=True):
        """vdso_mapping(single=True) -> mapping
        vdso_mapping(False) -> [mapping]

        Arguments:
            single(bool=True): Whether to only return the first
                mapping matched, or all of them.

        Returns :meth:`.process.get_mapping` with '[vdso]' and single as arguments.

        Example:

            >>> p = process(['cat'])
            >>> mapping = p.vdso_mapping()
            >>> mapping.path
            '[vdso]'
            >>> mapping.perms.execute
            True
            >>> mapping.perms.write
            False
            >>> hex(mapping.address) # doctest: +SKIP
            '0x7ffcf13af000'
            >>> mappings = p.vdso_mapping(single=False)
            >>> len(mappings)
            1

        """
        return self.get_mapping('[vdso]', single)
    
    def vvar_mapping(self, single=True):
        """vvar_mapping(single=True) -> mapping
        vvar_mapping(False) -> [mapping]

        Arguments:
            single(bool=True): Whether to only return the first
                mapping matched, or all of them.

        Returns :meth:`.process.get_mapping` with '[vvar]' and single as arguments.

        Example:

            >>> p = process(['cat'])
            >>> mapping = p.vvar_mapping()
            >>> mapping.path
            '[vvar]'
            >>> mapping.perms.execute
            False
            >>> mapping.perms.write
            False
            >>> hex(mapping.address) # doctest: +SKIP
            '0x7ffee5f60000'
            >>> mappings = p.vvar_mapping(single=False)
            >>> len(mappings)
            1

        """
        return self.get_mapping('[vvar]', single)
    
    def libc_mapping(self, single=True):
        """libc_mapping(single=True) -> mapping
        libc_mapping(False) -> [mapping]

        Arguments:
            single(bool=True): Whether to only return the first
                mapping matched, or all of them.

        Returns either the first libc mapping found in process memory,
        or all libc mappings, depending on "single". 

        Example:

            >>> p = process(['cat'])
            >>> p.sendline(b'meow')
            >>> p.recvline()
            b'meow\\n'
            >>> mapping = p.libc_mapping()
            >>> mapping.path # doctest: +ELLIPSIS
            '...libc...'
            >>> mapping.perms.execute
            False
            >>> mapping.perms.write
            False
            >>> hex(mapping.address) # doctest: +SKIP
            '0x7fbde7fd7000'
            >>>
            >>> mappings = p.libc_mapping(single=False)
            >>> len(mappings) > 1
            True
            >>> hex(mappings[1].address) # doctest: +SKIP
            '0x7fbde7ffd000'
            >>> mappings[0].end == mappings[1].start
            True
            >>> mappings[1].perms.execute
            True

        """
        all_maps = self.maps()

        if single:
            for mapping in all_maps:
                lib_basename = os.path.basename(mapping.path)
                if 'libc.so' in lib_basename or ('libc-' in lib_basename and '.so' in lib_basename):
                    return mapping
            return None

        l_mappings = []
        for mapping in all_maps:
            lib_basename = os.path.basename(mapping.path)
            if 'libc.so' in lib_basename or ('libc-' in lib_basename and '.so' in lib_basename):
                l_mappings.append(mapping)
        return l_mappings
    
    def musl_mapping(self, single=True):
        """musl_mapping(single=True) -> mapping
        musl_mapping(False) -> [mapping]

        Arguments:
            single(bool=True): Whether to only return the first
                mapping matched, or all of them.

        Returns either the first musl mapping found in process memory,
        or all musl mappings, depending on "single". 
        """
        all_maps = self.maps()

        if single:
            for mapping in all_maps:
                lib_basename = os.path.basename(mapping.path)
                if 'musl.so' in lib_basename or ('musl-' in lib_basename and '.so' in lib_basename):
                    return mapping
            return None
        
        m_mappings = []
        for mapping in all_maps:
            lib_basename = os.path.basename(mapping.path)
            if 'musl.so' in lib_basename or ('musl-' in lib_basename and '.so' in lib_basename):
                m_mappings.append(mapping)
        return m_mappings
    
    def elf_mapping(self, single=True):
        """elf_mapping(single=True) -> mapping
        elf_mapping(False) -> [mapping]

        Arguments:
            single(bool=True): Whether to only return the first
                mapping matched, or all of them.

        Returns :meth:`.process.get_mapping` with the :meth:`.process.elf` path and single as arguments.

        Example:

            >>> p = process(['cat'])
            >>> p.sendline(b'meow')
            >>> p.recvline()
            b'meow\\n'
            >>> mapping = p.elf_mapping()
            >>> mapping.path # doctest: +ELLIPSIS
            '...cat...'
            >>> mapping.perms.execute
            False
            >>> mapping.perms.write
            False
            >>> hex(mapping.address) # doctest: +SKIP
            '0x55a2abba0000'
            >>> mappings = p.elf_mapping(single=False)
            >>> len(mappings) > 1
            True
            >>> hex(mappings[1].address) # doctest: +SKIP
            '0x55a2abba2000'
            >>> mappings[0].end == mappings[1].start
            True
            >>> mappings[1].perms.execute
            True

        """
        return self.get_mapping(self.elf.path, single)

    def lib_size(self, path_value):
        """lib_size(path_value) -> int

        Arguments:
            path_value(str): The exact path of the shared library
            loaded by the process

        Returns the size of the shared library in process memory.
        If the library is not found, zero is returned.

        Example:

            >>> from pwn import *
            >>> p = process(['cat'])
            >>> libc_size = p.lib_size(p.libc.path)
            >>> hex(libc_size) # doctest: +SKIP
            '0x1d5000'
            >>> libc_mappings = p.libc_mapping(single=False)
            >>> libc_size == (libc_mappings[-1].end - libc_mappings[0].start)
            True

        """

        # Expecting this to be sorted
        lib_mappings = self.get_mapping(path_value, single=False)
        
        if len(lib_mappings) == 0:
            return 0
    
        is_contiguous = True
        total_size = lib_mappings[0].size
        for i in range(1, len(lib_mappings)):
            total_size += lib_mappings[i].size

            if lib_mappings[i].start != lib_mappings[i - 1].end:
                is_contiguous = False

        if not is_contiguous:
            log.warn("lib_size(): %s mappings aren't contiguous" % path_value)

        return total_size

    def address_mapping(self, address):
        """address_mapping(address) -> mapping
        
        Returns the mapping at the specified address.

        Example:

            >>> p = process(['cat'])
            >>> p.sendline(b'meow')
            >>> p.recvline()
            b'meow\\n'
            >>> libc = p.libc_mapping().address
            >>> heap = p.heap_mapping().address
            >>> elf = p.elf_mapping().address
            >>> p.address_mapping(libc).path # doctest: +ELLIPSIS
            '.../libc...'
            >>> p.address_mapping(heap + 0x123).path
            '[heap]'
            >>> p.address_mapping(elf + 0x1234).path # doctest: +ELLIPSIS
            '.../cat'
            >>> p.address_mapping(elf - 0x1234) == None
            True

        """

        all_maps = self.maps()
        for mapping in all_maps:
            if mapping.addr <= address < mapping.end:
                return mapping
        return None

    def libs(self):
        """libs() -> dict

        Return a dictionary mapping the path of each shared library loaded
        by the process to the address it is loaded at in the process' address
        space.
        """
        from pwnlib.util.proc import memory_maps
        maps_raw = self.poll() is not None and memory_maps(self.pid)

        if not maps_raw:
            import pwnlib.elf.elf

            with context.quiet:
                return pwnlib.elf.elf.ELF(self.executable).maps

        # Enumerate all of the libraries actually loaded right now.
        maps = {}
        for mapping in maps_raw:
            path = mapping.path
            if os.sep not in path: continue
            path = os.path.realpath(path)
            if path not in maps:
                maps[path]=0

        for lib in maps:
            path = os.path.realpath(lib)
            for mapping in maps_raw:
                if mapping.path == path:
                    address = mapping.addr.split('-')[0]
                    maps[lib] = int(address, 16)
                    break

        return maps

    @property
    def libc(self):
        """libc() -> ELF

        Returns an ELF for the libc for the current process.
        If possible, it is adjusted to the correct address
        automatically.

        Example:

        >>> p = process("/bin/cat")
        >>> libc = p.libc
        >>> libc # doctest: +SKIP
        ELF('/lib64/libc-...so')
        >>> p.close()
        """
        from pwnlib.elf import ELF

        for lib, address in self.libs().items():
            lib_basename = os.path.basename(lib)
            if 'libc.so' in lib_basename or ('libc-' in lib_basename and '.so' in lib_basename):
                e = ELF(lib)
                e.address = address
                return e

    @property
    def elf(self):
        """elf() -> pwnlib.elf.elf.ELF

        Returns an ELF file for the executable that launched the process.
        """
        import pwnlib.elf.elf
        return pwnlib.elf.elf.ELF(self.executable)

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
            raise RuntimeError(e) # AttributeError would route through __getattr__, losing original message
        self._corefile._hash = core_hash

        return self._corefile

    def leak(self, address, count=1):
        r"""Leaks memory within the process at the specified address.

        Arguments:
            address(int): Address to leak memory at
            count(int): Number of bytes to leak at that address.

        Example:

            >>> e = ELF(which('bash-static'))
            >>> p = process(e.path)

            In order to make sure there's not a race condition against
            the process getting set up...

            >>> p.sendline(b'echo hello')
            >>> p.recvuntil(b'hello')
            b'hello'

            Now we can leak some data!

            >>> p.leak(e.address, 4)
            b'\x7fELF'
        """
        # If it's running under qemu-user, don't leak anything.
        if 'qemu-' in os.path.realpath('/proc/%i/exe' % self.pid):
            self.error("Cannot use leaker on binaries under QEMU.")

        with open('/proc/%i/mem' % self.pid, 'rb') as mem:
            mem.seek(address)
            return mem.read(count) or None

    readmem = leak

    def writemem(self, address, data):
        r"""Writes memory within the process at the specified address.

        Arguments:
            address(int): Address to write memory
            data(bytes): Data to write to the address

        Example:
        
            Let's write data to  the beginning of the mapped memory of the  ELF.

            >>> context.clear(arch='i386')
            >>> address = 0x100000
            >>> data = cyclic(32)
            >>> assembly = shellcraft.nop() * len(data)

            Wait for one byte of input, then write the data to stdout

            >>> assembly += shellcraft.write(1, address, 1)
            >>> assembly += shellcraft.read(0, 'esp', 1)
            >>> assembly += shellcraft.write(1, address, 32)
            >>> assembly += shellcraft.exit()
            >>> asm(assembly)[32:]
            b'j\x01[\xb9\xff\xff\xef\xff\xf7\xd1\x89\xdaj\x04X\xcd\x801\xdb\x89\xe1j\x01Zj\x03X\xcd\x80j\x01[\xb9\xff\xff\xef\xff\xf7\xd1j Zj\x04X\xcd\x801\xdbj\x01X\xcd\x80'

            Assemble the binary and test it

            >>> elf = ELF.from_assembly(assembly, vma=address)
            >>> io = elf.process()
            >>> _ = io.recvuntil(b'\x90')
            >>> _ = io.writemem(address, data)
            >>> io.send(b'X')
            >>> io.recvall()
            b'aaaabaaacaaadaaaeaaafaaagaaahaaa'
        """

        if 'qemu-' in os.path.realpath('/proc/%i/exe' % self.pid):
            self.error("Cannot use leaker on binaries under QEMU.")

        with open('/proc/%i/mem' % self.pid, 'wb') as mem:
            mem.seek(address)
            return mem.write(data)


    @property
    def stdin(self):
        """Shorthand for ``self.proc.stdin``

        See: :obj:`.process.proc`
        """
        return self.proc.stdin
    @property
    def stdout(self):
        """Shorthand for ``self.proc.stdout``

        See: :obj:`.process.proc`
        """
        return self.proc.stdout
    @property
    def stderr(self):
        """Shorthand for ``self.proc.stderr``

        See: :obj:`.process.proc`
        """
        return self.proc.stderr

# Keep reading the process's output in a separate thread,
# since there's no non-blocking read in python on Windows.
def _read_in_thread(recv_queue, proc_stdout):
    try:
        while True:
            b = proc_stdout.read(1)
            if b:
                recv_queue.put(b)
            else:
                break
    except:
        # Ignore any errors during Python shutdown
        pass
