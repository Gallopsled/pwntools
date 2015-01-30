from .tube import tube
from ..timeout import Timeout
from ..util.misc import which
from ..context import context
from ..log import getLogger
import subprocess, fcntl, os, select

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
    """
    def __init__(self, args, shell = False, executable = None,
                 cwd = None, env = None, timeout = Timeout.default,
                 stderr_debug = False, level = None):
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

        self.args       = args
        self.executable = self.program = executable
        self.cwd        = cwd
        self.env        = env

        self.proc = subprocess.Popen(
            args, shell = shell, executable = executable,
            cwd = cwd, env = env,
            stdin = subprocess.PIPE, stdout = subprocess.PIPE,
            stderr = subprocess.PIPE if stderr_debug else subprocess.STDOUT)
        self.stop_noticed = False

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
        data = self.proc.stdout.read(numb)

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
