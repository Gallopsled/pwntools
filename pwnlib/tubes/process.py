import errno
import fcntl
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
    Implements a tube which talks to a process on stdin/stdout/stderr.

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
    """
    def __init__(self, args, shell = False, executable = None,
                 cwd = None, env = None, timeout = Timeout.default,
                 stdin  = None,
                 stdout = None,
                 stderr = None,
                 stderr_debug = False,
                 level = None,
                 close_fds = True):
        super(process, self).__init__(timeout, level = level)

        if executable:
            pass
        elif isinstance(args, (str, unicode)):
            executable = args
            args       = [args]
        elif isinstance(args, (list, tuple)):
            executable = args[0]
        else:
            self.error("process(): Do not understand the arguments %r" % args)

        # Did we specify something not in $PATH?
        if not which(executable):
            # If we specified a path to a binary, make it absolute.
            # This saves us the step of './binary'
            if os.path.exists(executable) and os.access(executable, os.X_OK):
                executable = os.path.abspath(executable)

            # Otherwise, there's no binary to execute
            else:
                self.error('%r is not set to executable (chmod +x %r)' % (executable, executable))

        # Python doesn't like when an arg in argv contains '\x00'
        # -> execve() arg 2 must contain only strings
        self.args = list(args)

        for i, arg in enumerate(self.args):
            if '\x00' in arg[:-1]:
                log.error('Inappropriate nulls in argv[%i]: %r' % (i, arg))

            self.args[i] = arg.rstrip('\x00')

        self.executable = self.program = executable
        self.cwd        = cwd
        self.env        = env

        master, slave   = None, None

        if stdin is None:
            stdin = subprocess.PIPE

        if stdout is None:
            # Make a pty pair for stdout
            master, slave = pty.openpty()

            # Set master and slave to raw mode
            tty.setraw(master)
            tty.setraw(slave)

            stdout = slave

        if stderr is None:
            stderr = stdout
        elif stderr_debug:
            log.error("Cannot capture stderr and send it all to debug")

        self.proc = subprocess.Popen(
            args, shell = shell, executable = executable,
            cwd = cwd, env = env,
            stdin = stdin, stdout = stdout,
            stderr = stderr,
            close_fds = close_fds,
            preexec_fn = os.setpgrp)

        self.stop_noticed = False

        if master and slave:
            self.proc.stdout = os.fdopen(master)
            os.close(slave)

        # Set in non-blocking mode so that a call to call recv(1000) will
        # return as soon as a the first byte is available
        fd = self.proc.stdout.fileno()
        fl = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)

        self.success("Started program %r" % self.program)
        self.debug("...with arguments %r" % args)

        def printer():
            try:
                while True:
                    line = self.proc.stderr.readline()
                    if line: self.debug(line.rstrip())
                    else: break
            except Exception:
                pass

        if stderr_debug:
            t = context.Thread(target=printer)
            t.daemon = True
            t.start()

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
        if self.proc.returncode != None and not self.stop_noticed:
            self.stop_noticed = True
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
        # First check if we are already dead
        self.poll()

        if not self.stop_noticed:
            try:
                self.proc.kill()
                self.stop_noticed = True
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
