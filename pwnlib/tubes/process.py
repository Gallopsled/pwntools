import ctypes
import errno
import fcntl
import logging
import os
import platform
import pty
import resource
import select
import signal
import subprocess
import tty

from ..context import context
from ..log import getLogger
from ..qemu import get_qemu_user
from ..timeout import Timeout
from ..util.misc import parse_ldd_output
from ..util.misc import which
from .tube import tube

log = getLogger(__name__)

PIPE = subprocess.PIPE
STDOUT = subprocess.STDOUT

class PTY(object): pass
PTY=PTY()

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
            Path to the binary to execute.  If ``None``, uses ``argv[0]``.
            Cannot be used with ``shell``.
        cwd(str):
            Working directory.  Uses the current working directory by default.
        env(dict):
            Environment variables.  By default, inherits from Python's environment.
        stdin(int):
            File object or file descriptor number to use for ``stdin``.
            By default, a pipe is used.  A pty can be used instead by setting
            this to ``process.PTY``.  This will cause programs to behave in an
            interactive manner (e.g.., ``python`` will show a ``>>>`` prompt).
            If the application reads from ``/dev/tty`` directly, use a pty.
        stdout(int):
            File object or file descriptor number to use for ``stdout``.
            By default, a pty is used so that any stdout buffering by libc
            routines is disabled.
            May also be ``subprocess.PIPE`` to use a normal pipe.
        stderr(int):
            File object or file descriptor number to use for ``stderr``.
            By default, ``stdout`` is used.
            May also be ``subprocess.PIPE`` to use a separate pipe,
            although the ``tube`` wrapper will not be able to read this data.
        close_fds(bool):
            Close all open file descriptors except stdin, stdout, stderr.
            By default, ``True`` is used.
        preexec_fn(callable):
            Callable to invoke immediately before calling ``execve``.
        raw(bool):
            Set the created pty to raw mode (i.e. disable echo and control
            characters).  ``True`` by default.  If no pty is created, this
            has no effect.
        aslr(bool):
            If set to ``False``, disable ASLR via ``personality`` (``setarch -R``)
            and ``setrlimit`` (``ulimit -s unlimited``).

            This disables ASLR for the target process.  However, the ``setarch``
            changes are lost if a ``setuid`` binary is executed.

            The default value is inherited from ``context.aslr``.
            See ``setuid`` below for additional options and information.
        setuid(bool):
            Used to control `setuid` status of the target binary, and the
            corresponding actions taken.

            By default, this value is ``None``, so no assumptions are made.

            If ``True``, treat the target binary as ``setuid``.
            This modifies the mechanisms used to disable ASLR on the process if
            ``aslr=False``.
            This is useful for debugging locally, when the exploit is a
            ``setuid`` binary.

            If ``False``, prevent ``setuid`` bits from taking effect on the
            target binary.  This is only supported on Linux, with kernels v3.5
            or greater.
        where(str):
            Where the process is running, used for logging purposes.
        display(list):
            List of arguments to display, instead of the main executable name.
        alarm(int):
            Set a SIGALRM alarm timeout on the process.

    Attributes:
        proc(subprocess)

    Examples:

        >>> p = process('python2')
        >>> p.sendline("print 'Hello world'")
        >>> p.sendline("print 'Wow, such data'");
        >>> '' == p.recv(timeout=0.01)
        True
        >>> p.shutdown('send')
        >>> p.proc.stdin.closed
        True
        >>> p.connected('send')
        False
        >>> p.recvline()
        'Hello world\n'
        >>> p.recvuntil(',')
        'Wow,'
        >>> p.recvregex('.*data')
        ' such data'
        >>> p.recv()
        '\n'
        >>> p.recv() # doctest: +ELLIPSIS
        Traceback (most recent call last):
        ...
        EOFError

        >>> p = process('cat')
        >>> d = open('/dev/urandom').read(4096)
        >>> p.recv(timeout=0.1)
        ''
        >>> p.write(d)
        >>> p.recvrepeat(0.1) == d
        True
        >>> p.recv(timeout=0.1)
        ''
        >>> p.shutdown('send')
        >>> p.wait_for_close()
        >>> p.poll()
        0

        >>> p = process('cat /dev/zero | head -c8', shell=True, stderr=open('/dev/null', 'w+'))
        >>> p.recv()
        '\x00\x00\x00\x00\x00\x00\x00\x00'

        >>> p = process(['python','-c','import os; print os.read(2,1024)'],
        ...             preexec_fn = lambda: os.dup2(0,2))
        >>> p.sendline('hello')
        >>> p.recvline()
        'hello\n'

        >>> stack_smashing = ['python','-c','open("/dev/tty","wb").write("stack smashing detected")']
        >>> process(stack_smashing).recvall()
        'stack smashing detected'

        >>> PIPE=subprocess.PIPE
        >>> process(stack_smashing, stdout=PIPE).recvall()
        ''

        >>> getpass = ['python','-c','import getpass; print getpass.getpass("XXX")']
        >>> p = process(getpass, stdin=process.PTY)
        >>> p.recv()
        'XXX'
        >>> p.sendline('hunter2')
        >>> p.recvall()
        '\nhunter2\n'

        >>> process('echo hello 1>&2', shell=True).recvall()
        'hello\n'

        >>> process('echo hello 1>&2', shell=True, stderr=PIPE).recvall()
        ''

        >>> a = process(['cat', '/proc/self/maps']).recvall()
        >>> b = process(['cat', '/proc/self/maps'], aslr=False).recvall()
        >>> with context.local(aslr=False):
        ...    c = process(['cat', '/proc/self/maps']).recvall()
        >>> a == b
        False
        >>> b == c
        True

        >>> process(['sh','-c','ulimit -s'], aslr=0).recvline()
        'unlimited\n'

        >>> io = process(['sh','-c','sleep 10; exit 7'], alarm=2)
        >>> io.poll(block=True) == -signal.SIGALRM
        True

        >>> binary = ELF.from_assembly('nop', arch='mips')
        >>> p = process(binary.path)
    """

    PTY = PTY

    #: Have we seen the process stop?
    _stop_noticed = False

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


        #: `subprocess.Popen` object
        self.proc = None

        if not shell:
            executable, argv, env = self._validate(cwd, executable, argv, env)

        # Permit invocation as process('sh') and process(['sh'])
        if isinstance(argv, (str, unicode)):
            argv = [argv]

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

        #: Full path to the executable
        self.executable = executable

        #: Arguments passed on argv
        self.argv = argv

        #: Environment passed on envp
        self.env = os.environ if env is None else env

        #: Directory the process was created in
        self.cwd          = cwd or os.path.curdir

        #: Alarm timeout of the process
        self.alarm        = alarm

        self.preexec_fn = preexec_fn
        self.display    = display or self.program

        message = "Starting %s process %r" % (where, self.display)

        if self.isEnabledFor(logging.DEBUG):
            if self.argv != [self.executable]: message += ' argv=%r ' % self.argv
            if self.env  != os.environ:        message += ' env=%r ' % self.env

        with self.progress(message) as p:

            if not self.aslr:
                self.warn_once("ASLR is disabled!")

            # In the event the binary is a foreign architecture,
            # and binfmt is not installed (e.g. when running on
            # Travis CI), re-try with qemu-XXX if we get an
            # 'Exec format error'.
            prefixes = [([], executable)]
            executables = [executable]
            exception = None

            for prefix, executable in prefixes:
                try:
                    self.proc = subprocess.Popen(args = prefix + argv,
                                                 shell = shell,
                                                 executable = executable,
                                                 cwd = cwd,
                                                 env = env,
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

        if self.pty is not None:
            if stdin is slave:
                self.proc.stdin = os.fdopen(os.dup(master), 'r+')
            if stdout is slave:
                self.proc.stdout = os.fdopen(os.dup(master), 'r+')
            if stderr is slave:
                self.proc.stderr = os.fdopen(os.dup(master), 'r+')

            os.close(master)
            os.close(slave)

        # Set in non-blocking mode so that a call to call recv(1000) will
        # return as soon as a the first byte is available
        fd = self.proc.stdout.fileno()
        fl = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)

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
            except:
                self.exception("Could not disable ASLR")

        # Assume that the user would prefer to have core dumps.
        resource.setrlimit(resource.RLIMIT_CORE, (-1, -1))

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
            except:
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
            from ..elf import ELF
            binary = ELF(self.executable)

        # If we're on macOS, this will never work.  Bail now.
        # if platform.mac_ver()[0]:
            # self.error("Cannot run ELF binaries on macOS")

        # Determine what architecture the binary is, and find the
        # appropriate qemu binary to run it.
        qemu = get_qemu_user(arch=binary.arch)
        if qemu:
            args = [qemu]
            if self.argv:
                args += ['-0', self.argv[0]]
            args += ['--']
            return [args, qemu]

        # If we get here, we couldn't run the binary directly, and
        # we don't have a qemu which can run it.
        self.exception(exception)

    @property
    def program(self):
        """Alias for ``executable``, for backward compatibility"""
        return self.executable

    def _validate(self, cwd, executable, argv, env):
        """
        Perform extended validation on the executable path, argv, and envp.

        Mostly to make Python happy, but also to prevent common pitfalls.
        """

        cwd = cwd or os.path.curdir

        #
        # Validate argv
        #
        # - Must be a list/tuple of strings
        # - Each string must not contain '\x00'
        #
        if isinstance(argv, (str, unicode)):
            argv = [argv]

        if not all(isinstance(arg, (str, unicode)) for arg in argv):
            self.error("argv must be strings: %r" % argv)

        # Create a duplicate so we can modify it
        argv = list(argv or [])

        for i, arg in enumerate(argv):
            if '\x00' in arg[:-1]:
                self.error('Inappropriate nulls in argv[%i]: %r' % (i, arg))

            argv[i] = arg.rstrip('\x00')

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

        # Do not change absolute paths to binaries
        if executable.startswith(os.path.sep):
            pass

        # If there's no path component, it's in $PATH or relative to the
        # target directory.
        #
        # For example, 'sh'
        elif os.path.sep not in executable and which(executable):
            executable = which(executable)

        # Either there is a path component, or the binary is not in $PATH
        # For example, 'foo/bar' or 'bar' with cwd=='foo'
        elif os.path.sep not in executable:
            executable = os.path.join(cwd, executable)

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
        env = dict(os.environ if env is None else env)

        for k,v in env.items():
            if not isinstance(k, (str, unicode)):
                self.error('Environment keys must be strings: %r' % k)
            if not isinstance(k, (str, unicode)):
                self.error('Environment values must be strings: %r=%r' % (k,v))
            if '\x00' in k[:-1]:
                self.error('Inappropriate nulls in env key: %r' % (k))
            if '\x00' in v[:-1]:
                self.error('Inappropriate nulls in env value: %r=%r' % (k, v))

            env[k.rstrip('\x00')] = v.rstrip('\x00')

        return executable, argv, env

    def _handles(self, stdin, stdout, stderr):
        master = slave = None

        if self.pty is not None:
            # Normally we could just use subprocess.PIPE and be happy.
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
        if block:
            self.wait_for_close()

        self.proc.poll()
        if self.proc.returncode != None and not self._stop_noticed:
            self._stop_noticed = True
            self.info("Process %r stopped with exit code %d" % (self.display, self.proc.returncode))

        return self.proc.returncode

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
        except IOError as (err, strerror):
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
            if timeout == None:
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
            if v[0] == errno.EINTR:
                return False

    def connected_raw(self, direction):
        if direction == 'any':
            return self.poll() == None
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
                self._stop_noticed = True
                self.info('Stopped program %r' % self.program)
            except OSError:
                pass


    def fileno(self):
        if not self.connected():
            self.error("A stopped program does not have a file number")

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
                raise Exception('Failed to disconnect from ' +
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

        If ``/proc/$PID/maps`` for the process cannot be accessed, the output
        of ``ldd`` alone is used.  This may give inaccurate results if ASLR
        is enabled.
        """
        with context.local(log_level='error'):
            ldd = process(['ldd', self.executable]).recvall()

        maps = parse_ldd_output(ldd)

        try:
            maps_raw = open('/proc/%d/maps' % self.pid).read()
        except IOError:
            return maps

        # Enumerate all of the libraries actually loaded right now.
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
        """
        from ..elf import ELF

        for lib, address in self.libs().items():
            if 'libc.so' in lib:
                e = ELF(lib)
                e.address = address
                return e

    @property
    def corefile(self):
        filename = 'core.%i' % (self.pid)
        process(['gcore', '-o', 'core', str(self.pid)]).wait()

        import pwnlib.elf.corefile
        return pwnlib.elf.corefile.Core(filename)

    def leak(self, address, count=1):
        """Leaks memory within the process at the specified address.

        Arguments:
            address(int): Address to leak memory at
            count(int): Number of bytes to leak at that address.
        """
        # If it's running under qemu-user, don't leak anything.
        if 'qemu-' in os.path.realpath('/proc/%i/exe' % self.pid):
            self.error("Cannot use leaker on binaries under QEMU.")

        with open('/proc/%i/mem' % self.pid, 'rb') as mem:
            mem.seek(address)
            return mem.read(count) or None
