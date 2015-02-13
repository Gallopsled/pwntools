import errno
import fcntl
import logging
import os
import pty
import select
import subprocess
import tty

from ..context import context
from ..log import getLogger
from ..timeout import Timeout
from ..util.misc import which
from .tube import tube

log = getLogger(__name__)

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
        timeout(int):
            Timeout to use on ``tube`` ``recv`` operations.
        stdin(int):
            File object or file descriptor number to use for ``stdin``.
            By default, a pipe is used.
        stdout(int):
            File object or file descriptor number to use for ``stdout``.
            By default, a pty is used.
            May also be ``subprocess.PIPE`` to use a normal pipe.
        stderr(int):
            File object or file descriptor number to use for ``stderr``.
            By default, ``stdout`` is used.
            May also be ``subprocess.PIPE`` to use a separate pipe,
            although the ``tube`` wrapper will not be able to read this data.

    Examples:

        >>> context.log_level='error'
        >>> p = process(which('python2'))
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
    """

    #: `subprocess.Popen` object
    proc = None

    #: Full path to the executable
    executable = None

    #: Full path to the executable
    program = None

    #: Arguments passed on argv
    argv = None

    #: Environment passed on envp
    env = None

    #: Directory the process was created in
    cwd = None

    #: Have we seen the process stop?
    _stop_noticed = False

    def __init__(self, argv,
                 shell = False,
                 executable = None,
                 cwd = None,
                 env = None,
                 timeout = Timeout.default,
                 stdin  = None,
                 stdout = None,
                 stderr = None,
                 level = None,
                 close_fds = True):
        super(process, self).__init__(timeout, level = level)

        if not shell:
            executable, argv, env = self._validate(cwd, executable, argv, env)

        stdin, stdout, stderr, master = self._handles(stdin, stdout, stderr)

        self.executable = self.program = executable
        self.argv       = argv
        self.env        = env
        self.cwd        = cwd or os.path.curdir

        message = "Starting program %r" % self.program

        if self.isEnabledFor(logging.DEBUG):
            if self.argv != [self.executable]: message += ' argv=%r ' % self.argv
            if self.env  != os.environ:        message += ' env=%r ' % self.env

        with self.progress(message) as p:
            self.proc = subprocess.Popen(args = argv,
                                         shell = shell,
                                         executable = executable,
                                         cwd = cwd,
                                         env = env,
                                         stdin = stdin,
                                         stdout = stdout,
                                         stderr = stderr,
                                         close_fds = close_fds,
                                         preexec_fn = os.setpgrp)

        if master:
            self.proc.stdout = os.fdopen(master)
            os.close(stdout)

        # Set in non-blocking mode so that a call to call recv(1000) will
        # return as soon as a the first byte is available
        fd = self.proc.stdout.fileno()
        fl = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)

    @staticmethod
    def _validate(cwd, executable, argv, env):
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
            log.error("argv must be strings: %r" % argv)

        # Create a duplicate so we can modify it
        argv = list(argv or [])

        for i, arg in enumerate(argv):
            if '\x00' in arg[:-1]:
                log.error('Inappropriate nulls in argv[%i]: %r' % (i, arg))

            argv[i] = arg.rstrip('\x00')

        #
        # Validate executable
        #
        # - Must be an absolute or relative path to the target executable
        # - If not, attempt to resolve the name in $PATH
        #
        if not executable:
            if not argv:
                log.error("Must specify argv or executable")
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
        else:
            executable = os.path.join(cwd, executable)

        if not os.path.exists(executable):
            log.error("%r does not exist")
        if not os.path.isfile(executable):
            log.error("%r is not a file")
        if not os.access(executable, os.X_OK):
            log.error("%r is not marked as executable (+x)")

        #
        # Validate environment
        #
        # - Must be a dictionary of {string:string}
        # - No strings may contain '\x00'
        #

        # Create a duplicate so we can modify it safely
        env = dict(env or os.environ)

        for k,v in env.items():
            if not isinstance(k, (str, unicode)):
                log.error('Environment keys must be strings: %r' % k)
            if not isinstance(k, (str, unicode)):
                log.error('Environment values must be strings: %r=%r' % (k,v))
            if '\x00' in k[:-1]:
                log.error('Inappropriate nulls in env key: %r' % (k))
            if '\x00' in v[:-1]:
                log.error('Inappropriate nulls in env value: %r=%r' % (k, v))

            env[k.rstrip('\x00')] = v.rstrip('\x00')

        return executable, argv, env

    @staticmethod
    def _handles(stdin, stdout, stderr):
        master = None

        if stdin is None:
            stdin = subprocess.PIPE

        if stdout is None:
            # Normally we could just use subprocess.PIPE and be happy.
            # Unfortunately, this results in undesired behavior when
            # printf() and similar functions buffer data instead of
            # sending it directly.
            #
            # By opening a PTY for STDOUT, the libc routines will not
            # buffer any data on STDOUT.
            master, slave = pty.openpty()


            # By making STDOUT a PTY, the OS will attempt to interpret
            # terminal control codes.  We don't want this, we want all
            # input passed exactly and perfectly to the process.
            tty.setraw(master)
            tty.setraw(slave)

            # Pick one side of the pty to pass to the child
            stdout = slave

        if stderr is None:
            stderr = stdout

        return stdin, stdout, stderr, master


    def kill(self):
        """kill()

        Kills the process.
        """

        self.close()

    def poll(self):
        """poll() -> int

        Poll the exit code of the process. Will return None, if the
        process has not yet finished and the exit code otherwise.
        """
        self.proc.poll()
        if self.proc.returncode != None and not self._stop_noticed:
            self._stop_noticed = True
            self.info("Program %r stopped with exit code %d" % (self.program, self.proc.returncode))

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
            #   File "/home/user/binjitsu/pwnlib/tubes/process.py", line 112, in can_recv_raw
            #     return select.select([self.proc.stdout], [], [], timeout) == ([self.proc.stdout], [], [])
            # ValueError: I/O operation on closed file
            raise EOFError

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

        if not self._stop_noticed:
            try:
                self.proc.kill()
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
