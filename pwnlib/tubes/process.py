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

from pwnlib import qemu
from pwnlib.context import context
from pwnlib.log import getLogger
from pwnlib.timeout import Timeout
from pwnlib.tubes.tube import tube
from pwnlib.util.hashes import sha256file
from pwnlib.util.misc import parse_ldd_output
from pwnlib.util.misc import which

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

        >>> p = process('python2')
        >>> p.sendline(b"print 'Hello world'")
        >>> p.sendline(b"print 'Wow, such data'");
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

    def __init__(self, argv = None,
                 shell = False,
                 executable = None,
                 cwd = None,
                 env = None,
                 stdin  = PIPE,
                 stdout = PTY,
                 stderr = STDOUT,
                 close_fds = True,
                 preexec_fn = lambda: None,
                 raw = True,
                 aslr = None,
                 setuid = None,
                 where = 'local',
                 display = None,
                 alarm = None,
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
        self.pty          = handles.index(PTY) if PTY in handles else None

        #: Whether the controlling TTY is set to raw mode
        self.raw          = raw

        #: Whether ASLR should be left on
        self.aslr         = aslr if aslr is not None else context.aslr

        #: Whether setuid is permitted
        self._setuid      = setuid if setuid is None else bool(setuid)

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
                                                 preexec_fn = self.__preexec_fn)
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
            self._cwd = os.readlink('/proc/%i/cwd' % self.pid)
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

        #
        # Validate argv
        #
        # - Must be a list/tuple of strings
        # - Each string must not contain '\x00'
        #
        if isinstance(argv, (six.text_type, six.binary_type)):
            argv = [argv]

        if not isinstance(argv, (list, tuple)):
            self.error('argv must be a list or tuple: %r' % argv)

        if not all(isinstance(arg, (six.text_type, six.binary_type)) for arg in argv):
            self.error("argv must be strings or bytes: %r" % argv)

        # Create a duplicate so we can modify it
        argv = list(argv or [])

        for i, oarg in enumerate(argv):
            if isinstance(oarg, six.text_type):
                arg = oarg.encode('utf-8')
            else:
                arg = oarg
            if b'\x00' in arg[:-1]:
                self.error('Inappropriate nulls in argv[%i]: %r' % (i, oarg))
            argv[i] = arg.rstrip(b'\x00')

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

        env = os.environ if env is None else env

        path = env.get('PATH')
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

        #
        # Validate environment
        #
        # - Must be a dictionary of {string:string}
        # - No strings may contain '\x00'
        #

        # Create a duplicate so we can modify it safely
        env2 = {}
        for k,v in env.items():
            if not isinstance(k, (bytes, six.text_type)):
                self.error('Environment keys must be strings: %r' % k)
            if not isinstance(k, (bytes, six.text_type)):
                self.error('Environment values must be strings: %r=%r' % (k,v))
            if isinstance(k, six.text_type):
                k = k.encode('utf-8')
            if isinstance(v, six.text_type):
                v = v.encode('utf-8', 'surrogateescape')
            if b'\x00' in k[:-1]:
                self.error('Inappropriate nulls in env key: %r' % (k))
            if b'\x00' in v[:-1]:
                self.error('Inappropriate nulls in env value: %r=%r' % (k, v))
            env2[k.rstrip(b'\x00')] = v.rstrip(b'\x00')

        return executable, argv, env2

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
        if hasattr(self.proc, attr):
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
            return not self.proc.stdin.closed
        elif direction == 'recv':
            return not self.proc.stdout.closed

    def close(self):
        if self.proc is None:
            return

        # First check if we are already dead
        self.poll()

        #close file descriptors
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


    def fileno(self):
        if not self.connected():
            self.error("A stopped process does not have a file number")

        return self.proc.stdout.fileno()

    def shutdown_raw(self, direction):
        if direction == "send":
            self.proc.stdin.close()

        if direction == "recv":
            self.proc.stdout.close()

        if False not in [self.proc.stdin.closed, self.proc.stdout.closed]:
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

    def libs(self):
        """libs() -> dict

        Return a dictionary mapping the path of each shared library loaded
        by the process to the address it is loaded at in the process' address
        space.
        """
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
                maps[path]=0

        for lib in maps:
            path = os.path.realpath(lib)
            for line in maps_raw.splitlines():
                if line.endswith(path):
                    address = line.split('-')[0]
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
            if 'libc.so' in lib or 'libc-' in lib:
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

            >>> e = ELF('/bin/bash-static')
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
