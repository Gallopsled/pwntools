import logging
import os
import re
import shutil
import string
import sys
import tarfile
import tempfile
import threading
import time

from .. import term
from ..context import context
from ..log import getLogger
from ..timeout import Timeout
from ..util import hashes
from ..util import misc
from ..util import safeeval
from .process import process
from .sock import sock

# Kill the warning line:
# No handlers could be found for logger "paramiko.transport"
paramiko_log = logging.getLogger("paramiko.transport")
h = logging.StreamHandler(file('/dev/null','w+'))
h.setFormatter(logging.Formatter())
paramiko_log.addHandler(h)

log = getLogger(__name__)

class ssh_channel(sock):

    #: Parent :class:`ssh` object
    parent = None

    #: Remote host
    host = None

    #: Return code, or ``None`` if the process has not returned
    #: Use :meth:`poll` to check.
    returncode = None

    #: ``True`` if a tty was allocated for this channel
    tty = False

    #: Environment specified for the remote process, or ``None``
    #: if the default environment was used
    env = None

    #: Command specified for the constructor
    process = None

    #: Working directory
    cwd = None

    #: PID of the process
    #: Only valid when instantiated through :meth:`ssh.process`
    pid = None

    #: Executable of the process
    #: Only valid when instantiated through :meth:`ssh.process`
    exe = None

    #: Arguments passed to the process
    #: Only valid when instantiated through :meth:`ssh.process`
    argv = None

    def __init__(self, parent, process = None, tty = False, wd = None, env = None, timeout = Timeout.default):
        super(ssh_channel, self).__init__(timeout)

        # keep the parent from being garbage collected in some cases
        self.parent = parent

        self.returncode = None
        self.host = parent.host
        self.tty  = tty
        self.env  = env
        self.process = process
        self.cwd  = wd

        env = env or {}
        msg = 'Opening new channel: %r' % ((process,) or 'shell')

        if isinstance(process, (list, tuple)):
            process = ' '.join(misc.sh_string(s) for s in process)

        if process and wd:
            process = "cd %s >/dev/null 2>&1; %s" % (misc.sh_string(wd), process)

        if process and env:
            for name, value in env.items():
                if not re.match('^[a-zA-Z_][a-zA-Z0-9_]*$', name):
                    log.error('run(): Invalid environment key $r' % name)
                process = '%s=%s %s' % (name, misc.sh_string(value), process)

        if process and tty:
            process = 'stty raw -ctlecho -echo; ' + process

        # If this object is enabled for DEBUG-level logging, don't hide
        # anything about the command that's actually executed.
        if process and log.isEnabledFor(logging.DEBUG):
            msg = 'Opening new channel: %r' % ((process,) or 'shell')

        with log.waitfor(msg) as h:
            import paramiko
            try:
                self.sock = parent.transport.open_session()
            except paramiko.ChannelException as e:
                if e.args == (1, 'Administratively prohibited'):
                    log.error("Too many sessions open! Use ssh_channel.close() or 'with'!")
                raise e

            if self.tty:
                self.sock.get_pty('xterm', term.width, term.height)

                def resizer():
                    if self.sock:
                        self.sock.resize_pty(term.width, term.height)

                self.resizer = resizer
                term.term.on_winch.append(self.resizer)
            else:
                self.resizer = None

            # Put stderr on stdout. This might not always be desirable,
            # but our API does not support multiple streams
            self.sock.set_combine_stderr(True)

            self.settimeout(self.timeout)

            if process:
                self.sock.exec_command(process)
            else:
                self.sock.invoke_shell()

            h.success()

    def kill(self):
        """kill()

        Kills the process.
        """

        self.close()

    def recvall(self, timeout = sock.forever):
        # We subclass tubes.sock which sets self.sock to None.
        #
        # However, we need to wait for the return value to propagate,
        # which may not happen by the time .close() is called by tube.recvall()
        tmp_sock = self.sock

        timeout = self.maximum if self.timeout is self.forever else self.timeout
        data = super(ssh_channel, self).recvall(timeout)

        # Restore self.sock to be able to call wait()
        self.sock = tmp_sock
        self.wait()

        # Again set self.sock to None
        self.sock = None

        return data

    def wait(self):
        return self.poll(block=True)

    def poll(self, block=False):
        """poll() -> int

        Poll the exit code of the process. Will return None, if the
        process has not yet finished and the exit code otherwise.
        """

        if self.returncode == None and hasattr(self, 'sock') and self.sock \
        and (block or self.sock.exit_status_ready()):
            while not self.sock.status_event.is_set():
                self.sock.status_event.wait(0.05)
            self.returncode = self.sock.recv_exit_status()

        return self.returncode

    def can_recv_raw(self, timeout):
        end = time.time() + timeout
        while time.time() < end:
            if self.sock.recv_ready():
                return True
            time.sleep(0.05)
        return False

    def interactive(self, prompt = term.text.bold_red('$') + ' '):
        """interactive(prompt = pwnlib.term.text.bold_red('$') + ' ')

        If not in TTY-mode, this does exactly the same as
        meth:`pwnlib.tubes.tube.tube.interactive`, otherwise
        it does mostly the same.

        An SSH connection in TTY-mode will typically supply its own prompt,
        thus the prompt argument is ignored in this case.
        We also have a few SSH-specific hacks that will ideally be removed
        once the :mod:`pwnlib.term` is more mature.
        """

        # If we are only executing a regular old shell, we need to handle
        # control codes (specifically Ctrl+C).
        #
        # Otherwise, we can just punt to the default implementation of interactive()
        if self.process is not None:
            return super(ssh_channel, self).interactive(prompt)

        log.info('Switching to interactive mode')

        # We would like a cursor, please!
        term.term.show_cursor()

        event = threading.Event()
        def recv_thread(event):
            while not event.is_set():
                try:
                    cur = self.recv(timeout = 0.05)
                    if cur == None:
                        continue
                    elif cur == '\a':
                        # Ugly hack until term unstands bell characters
                        continue
                    sys.stdout.write(cur)
                    sys.stdout.flush()
                except EOFError:
                    log.info('Got EOF while reading in interactive')
                    event.set()
                    break

        t = context.Thread(target = recv_thread, args = (event,))
        t.daemon = True
        t.start()

        while not event.is_set():
            if term.term_mode:
                try:
                    data = term.key.getraw(0.1)
                except KeyboardInterrupt:
                    data = [3] # This is ctrl-c
                except IOError:
                    if not event.is_set():
                        raise
            else:
                data = sys.stdin.read(1)
                if not data:
                    event.set()
                else:
                    data = [ord(data)]

            if data:
                try:
                    self.send(''.join(chr(c) for c in data))
                except EOFError:
                    event.set()
                    log.info('Got EOF while sending in interactive')

        while t.is_alive():
            t.join(timeout = 0.1)

        # Restore
        term.term.hide_cursor()

    def close(self):
        self.poll()
        while self.resizer in term.term.on_winch:
            term.term.on_winch.remove(self.resizer)
        super(ssh_channel, self).close()

    def spawn_process(self, *args, **kwargs):
        log.error("Cannot use spawn_process on an SSH channel.""")

    def _close_msg(self):
        log.info('Closed SSH channel with %s' % self.host)

class ssh_connecter(sock):
    def __init__(self, parent, host, port, timeout = Timeout.default):
        super(ssh_connecter, self).__init__(timeout)

        # keep the parent from being garbage collected in some cases
        self.parent = parent

        self.host  = parent.host
        self.rhost = host
        self.rport = port

        msg = 'Connecting to %s:%d via SSH to %s' % (self.rhost, self.rport, self.host)
        with log.waitfor(msg) as h:
            try:
                self.sock = parent.transport.open_channel('direct-tcpip', (host, port), ('127.0.0.1', 0))
            except Exception as e:
                self.exception(e.message)

            sockname = self.sock.get_transport().sock.getsockname()
            self.lhost = sockname[0]
            self.lport = sockname[1]

            h.success()

    def spawn_process(self, *args, **kwargs):
        log.error("Cannot use spawn_process on an SSH channel.""")

    def _close_msg(self):
        log.info("Closed remote connection to %s:%d via SSH connection to %s" % (self.rhost, self.rport, self.host))


class ssh_listener(sock):
    def __init__(self, parent, bind_address, port, timeout = Timeout.default):
        super(ssh_listener, self).__init__(timeout)

        # keep the parent from being garbage collected in some cases
        self.parent = parent

        self.host = parent.host

        try:
            self.port = parent.transport.request_port_forward(bind_address, port)
        except:
            log.error('Failed create a port forwarding')
            raise

        def accepter():
            msg = 'Waiting on port %d via SSH to %s' % (self.port, self.host)
            with log.waitfor(msg) as h:
                try:
                    self.sock = parent.transport.accept()
                    parent.transport.cancel_port_forward(bind_address, self.port)
                except:
                    self.sock = None
                    self.exception('Failed to get a connection')

            self.rhost, self.rport = self.sock.origin_addr
            h.success('Got connection from %s:%d' % (self.rhost, self.rport))

        self._accepter = context.Thread(target = accepter)
        self._accepter.daemon = True
        self._accepter.start()

    def _close_msg(self):
        log.info("Closed remote connection to %s:%d via SSH listener on port %d via %s" % (self.rhost, self.rport, self.port, self.host))

    def spawn_process(self, *args, **kwargs):
        log.error("Cannot use spawn_process on an SSH channel.""")

    def wait_for_connection(self):
        """Blocks until a connection has been established."""
        _ = self.sock
        return self

    def __getattr__(self, key):
        if key == 'sock':
            while self._accepter.is_alive():
                self._accepter.join(timeout = 0.1)
            return self.sock
        else:
            return getattr(super(ssh_listener, self), key)


class ssh(Timeout):

    #: Remote host name (``str``)
    host = None

    #: Remote port (``int``)
    port = None

    #: Working directory (``str``)
    cwd = None

    #: Enable caching of SSH downloads (``bool``)
    cache = True

    #: Paramiko SSHClient which backs this object
    client = None

    #: Paramiko SFTPClient object which is used for file transfers.
    #: Set to ``None`` to disable ``sftp``.
    sftp = None

    #: PID of the remote ``sshd`` process servicing this connection.
    pid = None

    def __init__(self, user, host, port = 22, password = None, key = None,
                 keyfile = None, proxy_command = None, proxy_sock = None,
                 timeout = Timeout.default, cache = True):
        """Creates a new ssh connection.

        Arguments:
            user(str): The username to log in with
            host(str): The hostname to connect to
            port(int): The port to connect to
            password(str): Try to authenticate using this password
            key(str): Try to authenticate using this private key. The string should be the actual private key.
            keyfile(str): Try to authenticate using this private key. The string should be a filename.
            proxy_command(str): Use this as a proxy command. It has approximately the same semantics as ProxyCommand from ssh(1).
            proxy_sock(str): Use this socket instead of connecting to the host.
            timeout: Timeout, in seconds
            cache: Cache downloaded files (by hash/size/timestamp)

        NOTE: The proxy_command and proxy_sock arguments is only available if a
        fairly new version of paramiko is used."""
        super(ssh, self).__init__(timeout)

        self.host            = host
        self.port            = port
        self.user            = user
        self.password        = password
        self.key             = key
        self.keyfile         = keyfile
        self._cachedir       = os.path.join(tempfile.gettempdir(), 'pwntools-ssh-cache')
        self.cwd             = '.'
        self.cache           = cache

        misc.mkdir_p(self._cachedir)

        import paramiko

        # Make a basic attempt to parse the ssh_config file
        try:
            config_file = os.path.expanduser('~/.ssh/config')

            if os.path.exists(config_file):
                ssh_config  = paramiko.SSHConfig()
                ssh_config.parse(file(config_file))
                host_config = ssh_config.lookup(host)
                if 'hostname' in host_config:
                    self.host = host = host_config['hostname']
                if not keyfile and 'identityfile' in host_config:
                    keyfile = host_config['identityfile'][0]
        except Exception as e:
            log.debug("An error occurred while parsing ~/.ssh/config:\n%s" % e)

        keyfiles = [os.path.expanduser(keyfile)] if keyfile else []

        msg = 'Connecting to %s on port %d' % (host, port)
        with log.waitfor(msg) as h:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            known_hosts = os.path.expanduser('~/.ssh/known_hosts')
            if os.path.exists(known_hosts):
                self.client.load_host_keys(known_hosts)

            has_proxy = (proxy_sock or proxy_command) and True
            if has_proxy:
                if 'ProxyCommand' not in dir(paramiko):
                    log.error('This version of paramiko does not support proxies.')

                if proxy_sock and proxy_command:
                    log.error('Cannot have both a proxy command and a proxy sock')

                if proxy_command:
                    proxy_sock = paramiko.ProxyCommand(proxy_command)
                self.client.connect(host, port, user, password, key, keyfiles, self.timeout, compress = True, sock = proxy_sock)
            else:
                self.client.connect(host, port, user, password, key, keyfiles, self.timeout, compress = True)

            self.transport = self.client.get_transport()

            h.success()

        try:
            self.sftp = self.transport.open_sftp_client()
        except Exception:
            self.sftp = None


        with context.local(log_level='error'):
            try:
                self.pid = int(self.system('echo $PPID').recv(timeout=1))
            except Exception:
                self.pid = None


    def __enter__(self, *a):
        return self

    def __exit__(self, *a, **kw):
        self.close()

    def shell(self, shell = None, tty = True, timeout = Timeout.default):
        """shell(shell = None, tty = True, timeout = Timeout.default) -> ssh_channel

        Open a new channel with a shell inside.

        Arguments:
            shell(str): Path to the shell program to run.
                If ``None``, uses the default shell for the logged in user.
            tty(bool): If ``True``, then a TTY is requested on the remote server.

        Returns:
            Return a :class:`pwnlib.tubes.ssh.ssh_channel` object.

        Examples:
            >>> s =  ssh(host='example.pwnme',
            ...         user='demouser',
            ...         password='demopass')
            >>> sh = s.shell('/bin/sh')
            >>> sh.sendline('echo Hello; exit')
            >>> print 'Hello' in sh.recvall()
            True
        """
        return self.run(shell, tty, timeout = timeout)

    def process(self, argv=None, executable=None, tty = True, cwd = None, env = None, timeout = Timeout.default, run = True,
                stdin=0, stdout=1, stderr=2):
        r"""
        Executes a process on the remote server, in the same fashion
        as pwnlib.tubes.process.process.

        To achieve this, a Python script is created to call ``os.execve``
        with the appropriate arguments.

        As an added bonus, the ``ssh_channel`` object returned has a
        ``pid`` property for the process pid.

        Arguments:
            argv(list):
                List of arguments to pass into the process
            executable(str):
                Path to the executable to run.
                If ``None``, ``argv[0]`` is used.
            tty(bool):
                Request a `tty` from the server.  This usually fixes buffering problems
                by causing `libc` to write data immediately rather than buffering it.
                However, this disables interpretation of control codes (e.g. Ctrl+C)
                and breaks `.shutdown`.
            cwd(str):
                Working directory.  If ``None``, uses the working directory specified
                on :attr:`cwd` or set via :meth:`set_working_directory`.
            env(dict):
                Environment variables to set in the child.  If ``None``, inherits the
                default environment.
            timeout(int):
                Timeout to set on the `tube` created to interact with the process.
            run(bool):
                Set to ``True`` to run the program (default).
                If ``False``, returns the path to an executable Python script on the
                remote server which, when executed, will do it.
            stdin(int, str):
                If an integer, replace stdin with the numbered file descriptor.
                If a string, a open a file with the specified path and replace
                stdin with its file descriptor.  May also be one of ``sys.stdin``,
                ``sys.stdout``, ``sys.stderr``.  If ``None``, the file descriptor is closed.
            stdout(int, str):
                See ``stdin``.
            stderr(int, str):
                See ``stdin``.

        Returns:
            A new SSH channel, or a path to a script if ``run=False``.

        Notes:
            Requires Python on the remote server.

        Examples:
            >>> s = ssh(host='example.pwnme',
            ...         user='demouser',
            ...         password='demopass')
            >>> sh = s.process('sh', env={'PS1':''})
            >>> sh.sendline('echo Hello; exit')
            >>> sh.recvall()
            'Hello\n'
            >>> s.process(['/bin/echo', '\xff']).recvall()
            '\xff\n'
            >>> s.process(['readlink', '/proc/self/exe']).recvall()
            '/bin/readlink\n'
            >>> s.process(['LOLOLOL', '/proc/self/exe'], executable='readlink').recvall()
            '/bin/readlink\n'
            >>> s.process(['LOLOLOL\x00', '/proc/self/cmdline'], executable='cat').recvall()
            'LOLOLOL\x00/proc/self/cmdline\x00'
            >>> sh = s.process(executable='/bin/sh')
            >>> sh.pid in pidof('sh')
            True
            >>> s.process(['pwd'], cwd='/tmp').recvall()
            '/tmp\n'
            >>> p = s.process(['python','-c','import os; print os.read(2, 1024)'], stderr=0)
            >>> p.send('hello')
            >>> p.recv()
            'hello\n'
            >>> s.process(['/bin/echo', 'hello']).recvall()
            'hello\n'
            >>> s.process(['/bin/echo', 'hello'], stdout='/dev/null').recvall()
            ''

        """
        if not argv and not executable:
            log.error("Must specify argv or executable")

        argv      = argv or []

        if isinstance(argv, (str, unicode)):
            argv = [argv]

        if not isinstance(argv, (list, tuple)):
            log.error('argv must be a list or tuple')

        # Python doesn't like when an arg in argv contains '\x00'
        # -> execve() arg 2 must contain only strings
        for i, arg in enumerate(argv):
            if '\x00' in arg[:-1]:
                log.error('Inappropriate nulls in argv[%i]: %r' % (i, arg))
            argv[i] = arg.rstrip('\x00')

        executable = executable or argv[0]
        cwd        = cwd or self.cwd or '.'

        # Validate, since failures on the remote side will suck.
        if not isinstance(executable, str):
            log.error("executable / argv[0] must be a string: %r" % executable)
        if not isinstance(argv, (list, tuple)):
            log.error("argv must be a list or tuple: %r" % argv)
        if env is not None and not isinstance(env, dict):
            log.error("env must be a dict: %r") % env
        if not all(isinstance(s, str) for s in argv):
            log.error("argv must only contain strings: %r" % argv)

        # Allow passing in sys.stdin/stdout/stderr objects
        stdin  = {sys.stdin: 0, sys.stdout:1, sys.stderr:2}.get(stdin, stdin)
        stdout = {sys.stdin: 0, sys.stdout:1, sys.stderr:2}.get(stdout, stdout)
        stderr = {sys.stdin: 0, sys.stdout:1, sys.stderr:2}.get(stderr, stderr)

        script = r"""
#!/usr/bin/env python
import os, sys
exe   = %r
argv  = %r
env   = %r

os.chdir(%r)

if env is None:
    env = os.environ

def is_exe(path):
    return os.path.isfile(path) and os.access(path, os.X_OK)

PATH = os.environ['PATH'].split(os.pathsep)

if os.path.sep not in exe and not is_exe(exe):
    for path in PATH:
        test_path = os.path.join(path, exe)
        if is_exe(test_path):
            exe = test_path
            break

if not is_exe(exe):
    sys.stderr.write('0\n')
    sys.stderr.write("{} is not executable or does not exist in {}".format(exe,PATH))
    sys.exit(-1)

if sys.argv[-1] == 'check':
    sys.stdout.write("1\n")
    sys.stdout.write(str(os.getpid()) + "\n")
    sys.stdout.flush()

for fd, newfd in {0: %r, 1: %r, 2:%r}.items():
    if newfd is None:
        close(fd)
    elif isinstance(newfd, str):
        os.close(fd)
        os.open(newfd, os.O_RDONLY if fd == 0 else (os.O_RDWR|os.O_CREAT))
    elif isinstance(newfd, int) and newfd != fd:
        os.dup2(fd, newfd)
        if newfd > 2:
            os.close(newfd)

os.execve(exe, argv, env)
""" % (executable, argv, env, cwd, stdin, stdout, stderr)

        script = script.lstrip()

        log.debug("Created execve script:\n" + script)

        if not run:
            with context.local(log_level='error'):
                tmpfile = self.mktemp('-t', 'pwnlib-execve-XXXXXXXXXX')
                self.chmod('+x', tmpfile)

            log.info("Uploading execve script to %r" % tmpfile)
            self.upload_data(script, tmpfile)
            return tmpfile

        execve_repr = "execve(%r, %s, %s)" % (executable, argv, env or 'os.environ')

        with log.progress('Opening new channel: %s' % execve_repr) as h:

            script = misc.sh_string(script)
            with context.local(log_level='error'):
                python = self.run('test -x "$(which python 2>&1)" && exec python -c %s check; echo 2' % script)
            result = safeeval.const(python.recvline())

            # If an error occurred, try to grab as much output
            # as we can.
            if result != 1:
                error_message = python.recvrepeat(timeout=1)

            if result == 0:
                log.error("%r does not exist or is not executable" % executable)
            elif result == 2:
                log.error("python is not installed on the remote system %r" % self.host)
            elif result != 1:
                h.failure("something bad happened:\n%s" % error_message)

            python.pid  = safeeval.const(python.recvline())
            python.argv = argv
            python.exe  = executable

        return python

    def system(self, process, tty = True, wd = None, env = None, timeout = Timeout.default):
        r"""system(process, tty = True, wd = None, env = None, timeout = Timeout.default) -> ssh_channel

        Open a new channel with a specific process inside. If `tty` is True,
        then a TTY is requested on the remote server.

        Return a :class:`pwnlib.tubes.ssh.ssh_channel` object.

        Examples:
            >>> s =  ssh(host='example.pwnme',
            ...         user='demouser',
            ...         password='demopass')
            >>> py = s.run('python -i')
            >>> _ = py.recvuntil('>>> ')
            >>> py.sendline('print 2+2')
            >>> py.sendline('exit')
            >>> print repr(py.recvline())
            '4\n'
        """

        if wd is None:
            wd = self.cwd

        return ssh_channel(self, process, tty, wd, env, timeout)

    #: Backward compatibility.  Use :meth:`system`
    run = system

    def run_to_end(self, process, tty = False, wd = None, env = None):
        r"""run_to_end(process, tty = False, timeout = Timeout.default, env = None) -> str

        Run a command on the remote server and return a tuple with
        (data, exit_status). If `tty` is True, then the command is run inside
        a TTY on the remote server.

        Examples:
            >>> s =  ssh(host='example.pwnme',
            ...         user='demouser',
            ...         password='demopass')
            >>> print s.run_to_end('echo Hello; exit 17')
            ('Hello\n', 17)
            """

        with context.local(log_level = 'ERROR'):
            c = self.run(process, tty, wd = wd, timeout = Timeout.default)
            data = c.recvall()
            retcode = c.wait()
            c.close()
            return data, retcode

    def connect_remote(self, host, port, timeout = Timeout.default):
        r"""connect_remote(host, port, timeout = Timeout.default) -> ssh_connecter

        Connects to a host through an SSH connection. This is equivalent to
        using the ``-L`` flag on ``ssh``.

        Returns a :class:`pwnlib.tubes.ssh.ssh_connecter` object.

        Examples:
            >>> from pwn import *
            >>> l = listen()
            >>> s =  ssh(host='example.pwnme',
            ...         user='demouser',
            ...         password='demopass')
            >>> a = s.connect_remote(s.host, l.lport)
            >>> b = l.wait_for_connection()
            >>> a.sendline('Hello')
            >>> print repr(b.recvline())
            'Hello\n'
        """

        return ssh_connecter(self, host, port, timeout)

    def listen_remote(self, port = 0, bind_address = '', timeout = Timeout.default):
        r"""listen_remote(port = 0, bind_address = '', timeout = Timeout.default) -> ssh_connecter

        Listens remotely through an SSH connection. This is equivalent to
        using the ``-R`` flag on ``ssh``.

        Returns a :class:`pwnlib.tubes.ssh.ssh_listener` object.

        Examples:

            >>> from pwn import *
            >>> s =  ssh(host='example.pwnme',
            ...         user='demouser',
            ...         password='demopass')
            >>> l = s.listen_remote()
            >>> a = remote(s.host, l.port)
            >>> b = l.wait_for_connection()
            >>> a.sendline('Hello')
            >>> print repr(b.recvline())
            'Hello\n'
        """

        return ssh_listener(self, bind_address, port, timeout)

    def __getitem__(self, attr):
        """Permits indexed access to run commands over SSH

        Examples:

            >>> s =  ssh(host='example.pwnme',
            ...         user='demouser',
            ...         password='demopass')
            >>> print s['echo hello']
            hello
        """
        return self.__getattr__(attr)()

    def __call__(self, attr):
        """Permits function-style access to run commands over SSH

        Examples:

            >>> s =  ssh(host='example.pwnme',
            ...         user='demouser',
            ...         password='demopass')
            >>> print repr(s('echo hello'))
            'hello'
        """
        return self.__getattr__(attr)()

    def __getattr__(self, attr):
        """Permits member access to run commands over SSH

        Examples:

            >>> s =  ssh(host='example.pwnme',
            ...         user='demouser',
            ...         password='demopass')
            >>> s.echo('hello')
            'hello'
            >>> s.whoami()
            'demouser'
            >>> s.echo(['huh','yay','args'])
            'huh yay args'
        """
        bad_attrs = [
            'trait_names',          # ipython tab-complete
        ]

        if attr in self.__dict__ \
        or attr in bad_attrs \
        or attr.startswith('_'):
            raise AttributeError

        def runner(*args):
            if len(args) == 1 and isinstance(args[0], (list, tuple)):
                command = [attr] + args[0]
            else:
                command = ' '.join((attr,) + args)

            return self.run(command).recvall().strip()
        return runner

    def connected(self):
        """Returns True if we are connected.

        Example:

            >>> s =  ssh(host='example.pwnme',
            ...         user='demouser',
            ...         password='demopass')
            >>> s.connected()
            True
            >>> s.close()
            >>> s.connected()
            False
        """
        return bool(self.client and self.client.get_transport().is_active())

    def close(self):
        """Close the connection."""
        if self.client:
            self.client.close()
            self.client = None
            log.info("Closed connection to %r" % self.host)

    def _libs_remote(self, remote):
        """Return a dictionary of the libraries used by a remote file."""
        cmd = '(ulimit -s unlimited; ldd %s > /dev/null && (LD_TRACE_LOADED_OBJECTS=1 %s || ldd %s)) 2>/dev/null'
        arg = misc.sh_string(remote)
        data, status = self.run_to_end(cmd % (arg, arg, arg))
        if status != 0:
            log.error('Unable to find libraries for %r' % remote)
            return {}

        return misc.parse_ldd_output(data)

    def _get_fingerprint(self, remote):
        arg = misc.sh_string(remote)
        cmd = '(openssl sha256 || sha256 || sha256sum) 2>/dev/null < %s' % (arg)
        data, status = self.run_to_end(cmd)

        if status != 0:
            return None

        # OpenSSL outputs in the format of...
        # (stdin)= e3b0c4429...
        data = data.replace('(stdin)= ','')

        # sha256 and sha256sum outputs in the format of...
        # e3b0c442...  -
        data = data.replace('-','')

        return data.strip()

    def _get_cachefile(self, fingerprint):
        return os.path.join(self._cachedir, fingerprint)

    def _verify_local_fingerprint(self, fingerprint):
        if not set(fingerprint).issubset(string.hexdigits) or \
           len(fingerprint) != 64:
            log.error('Invalid fingerprint %r' % fingerprint)
            return False

        local = self._get_cachefile(fingerprint)
        if not os.path.isfile(local):
            return False

        if hashes.sha256filehex(local) == fingerprint:
            return True
        else:
            os.unlink(local)
            return False

    def _download_raw(self, remote, local, h):
        def update(has, total):
            h.status("%s/%s" % (misc.size(has), misc.size(total)))

        if self.sftp:
            self.sftp.get(remote, local, update)
            return

        total, exitcode = self.run_to_end('wc -c <' + misc.sh_string(remote))

        if exitcode != 0:
            h.failure("%r does not exist or is not accessible" % remote)
            return

        total = int(total)

        with context.local(log_level = 'ERROR'):
            c = self.run('cat ' + misc.sh_string(remote))
        data = ''

        while True:
            try:
                data += c.recv()
            except EOFError:
                break
            update(len(data), total)

        result = c.wait()
        if result != 0:
            h.failure('Could not download file %r (%r)' % (remote, result))
            return

        with open(local, 'w') as fd:
            fd.write(data)

    def _download_to_cache(self, remote, p):

        with context.local(log_level='error'):
            remote = self.readlink('-f',remote)

        fingerprint = self._get_fingerprint(remote)
        if fingerprint is None:
            local = os.path.normpath(remote)
            local = os.path.basename(local)
            local += time.strftime('-%Y-%m-%d-%H:%M:%S')
            local = os.path.join(self._cachedir, local)

            self._download_raw(remote, local, p)
            return local

        local = self._get_cachefile(fingerprint)

        if self.cache and self._verify_local_fingerprint(fingerprint):
            p.success('Found %r in ssh cache' % remote)
        else:
            self._download_raw(remote, local, p)

            if not self._verify_local_fingerprint(fingerprint):
                p.failure('Could not download file %r' % remote)

        return local

    def download_data(self, remote):
        """Downloads a file from the remote server and returns it as a string.

        Arguments:
            remote(str): The remote filename to download.


        Examples:
            >>> with file('/tmp/bar','w+') as f:
            ...     f.write('Hello, world')
            >>> s =  ssh(host='example.pwnme',
            ...         user='demouser',
            ...         password='demopass',
            ...         cache=False)
            >>> s.download_data('/tmp/bar')
            'Hello, world'
            >>> s.sftp = False
            >>> s.download_data('/tmp/bar')
            'Hello, world'

        """
        with log.progress('Downloading %r' % remote) as p:
            with open(self._download_to_cache(remote, p)) as fd:
                return fd.read()

    def download_file(self, remote, local = None):
        """Downloads a file from the remote server.

        The file is cached in /tmp/binjitsu-ssh-cache using a hash of the file, so
        calling the function twice has little overhead.

        Arguments:
            remote(str): The remote filename to download
            local(str): The local filename to save it to. Default is to infer it from the remote filename.
        """


        if not local:
            local = os.path.basename(os.path.normpath(remote))

        if self.cwd and os.path.basename(remote) == remote:
            remote = os.path.join(self.cwd, remote)

        with log.progress('Downloading %r to %r' % (remote, local)) as p:
            local_tmp = self._download_to_cache(remote, p)

        # Check to see if an identical copy of the file already exists
        if not os.path.exists(local) or hashes.sha256filehex(local_tmp) != hashes.sha256filehex(local):
            shutil.copy2(local_tmp, local)

    def download_dir(self, remote=None, local=None):
        """Recursively uploads a directory onto the remote server

        Arguments:
            local: Local directory
            remote: Remote directory
        """
        remote   = remote or self.cwd or '.'


        if self.sftp:
            remote = str(self.sftp.normalize(remote))
        else:
            with context.local(log_level='error'):
                remote = self.system('readlink -f %s' % remote)

        dirname  = os.path.dirname(remote)
        basename = os.path.basename(remote)

        local    = local or '.'
        local    = os.path.expanduser(local)

        log.info("Downloading %r to %r" % (basename,local))

        with context.local(log_level='error'):
            remote_tar = self.mktemp()
            tar = self.system('tar -C %s -czf %s %s' % (dirname, remote_tar, basename))

            if 0 != tar.wait():
                log.error("Could not create remote tar")

            local_tar = tempfile.NamedTemporaryFile(suffix='.tar.gz')
            self.download_file(remote_tar, local_tar.name)

            tar = tarfile.open(local_tar.name)
            tar.extractall(local)


    def upload_data(self, data, remote):
        """Uploads some data into a file on the remote server.

        Arguments:
            data(str): The data to upload.
            remote(str): The filename to upload it to.

        Examoles:
            >>> s =  ssh(host='example.pwnme',
            ...         user='demouser',
            ...         password='demopass')
            >>> s.upload_data('Hello, world', '/tmp/upload_foo')
            >>> print file('/tmp/upload_foo').read()
            Hello, world
            >>> s.sftp = False
            >>> s.upload_data('Hello, world', '/tmp/upload_bar')
            >>> print file('/tmp/upload_bar').read()
            Hello, world
        """
        # If a relative path was provided, prepend the cwd
        if os.path.normpath(remote) == os.path.basename(remote):
            remote = os.path.join(self.cwd or '.', remote)

        if self.sftp:
            with tempfile.NamedTemporaryFile() as f:
                f.write(data)
                f.flush()
                self.sftp.put(f.name, remote)
                return

        with context.local(log_level = 'ERROR'):
            s = self.run('cat>' + misc.sh_string(remote), tty=False)
            s.send(data)
            s.shutdown('send')
            data   = s.recvall()
            result = s.wait()
            if result != 0:
                log.error("Could not upload file %r (%r)\n%s" % (remote, result, data))


    def upload_file(self, filename, remote = None):
        """Uploads a file to the remote server. Returns the remote filename.

        Arguments:
        filename(str): The local filename to download
        remote(str): The remote filename to save it to. Default is to infer it from the local filename."""


        if remote == None:
            remote = os.path.normpath(filename)
            remote = os.path.basename(remote)

            if self.cwd:
                remote = os.path.join(self.cwd, remote)

        with open(filename) as fd:
            data = fd.read()

        log.info("Uploading %r to %r" % (filename,remote))
        self.upload_data(data, remote)

        return remote

    def upload_dir(self, local, remote=None):
        """Recursively uploads a directory onto the remote server

        Arguments:
            local: Local directory
            remote: Remote directory
        """

        remote    = remote or self.cwd or '.'

        local     = os.path.expanduser(local)
        dirname   = os.path.dirname(local)
        basename  = os.path.basename(local)

        if not os.path.isdir(local):
            log.error("%r is not a directory" % local)

        msg = "Uploading %r to %r" % (basename,remote)
        with log.waitfor(msg) as w:
            # Generate a tarfile with everything inside of it
            local_tar  = tempfile.mktemp()
            with tarfile.open(local_tar, 'w:gz') as tar:
                tar.add(local, basename)

            # Upload and extract it
            with context.local(log_level='error'):
                remote_tar = self.mktemp('--suffix=.tar.gz')
                self.upload_file(local_tar, remote_tar)

                untar = self.run('cd %s && tar -xzf %s' % (remote, remote_tar))
                message = untar.recvrepeat(2)

                if untar.wait() != 0:
                    log.error("Could not untar %r on the remote end\n%s" % (remote_tar, message))

    def upload(self, file_or_directory, remote=None):
        if os.path.isfile(file_or_directory):
            return self.upload_file(file_or_directory, remote)

        if os.path.isdir(file_or_directory):
            return self.upload_dir(file_or_directory, remote)

    def download(self, file_or_directory, remote=None):
        if not self.sftp:
            log.error("Cannot determine remote file type without SFTP")

        if 0 == self.system('test -d %s' % file_or_directory).wait():
            self.download_dir(file_or_directory, remote)
        else:
            self.download_file(file_or_directory, remote)

    put = upload
    get = download

    def libs(self, remote, directory = None):
        """Downloads the libraries referred to by a file.

        This is done by running ldd on the remote server, parsing the output
        and downloading the relevant files.

        The directory argument specified where to download the files. This defaults
        to './$HOSTNAME' where $HOSTNAME is the hostname of the remote server."""

        libs = self._libs_remote(remote)

        remote = self.readlink('-f',remote).strip()
        libs[remote] = 0

        if directory == None:
            directory = self.host

        directory = os.path.realpath(directory)

        res = {}

        seen = set()

        for lib, addr in libs.items():
            local = os.path.realpath(os.path.join(directory, '.' + os.path.sep + lib))
            if not local.startswith(directory):
                log.warning('This seems fishy: %r' % lib)
                continue

            misc.mkdir_p(os.path.dirname(local))

            if lib not in seen:
                self.download_file(lib, local)
                seen.add(lib)
            res[local] = addr

        return res

    def interactive(self, shell=None):
        """Create an interactive session.

        This is a simple wrapper for creating a new
        :class:`pwnlib.tubes.ssh.ssh_channel` object and calling
        :meth:`pwnlib.tubes.ssh.ssh_channel.interactive` on it."""

        s = self.shell(shell)

        if self.cwd:
            s.sendline('cd ' + misc.sh_string(self.cwd))

        s.interactive()
        s.close()

    def set_working_directory(self, wd = None):
        """Sets the working directory in which future commands will
        be run (via ssh.run) and to which files will be uploaded/downloaded
        from if no path is provided

        Note:
            This uses ``mktemp -d`` under the covers, sets permissions
            on the directory to ``0700``.  This means that setuid binaries
            will **not** be able to access files created in this directory.

            In order to work around this, we also ``chmod +x`` the directory.

        Arguments:
            wd(string): Working directory.  Default is to auto-generate a directory
                based on the result of running 'mktemp -d' on the remote machine.

        Examples:
            >>> s =  ssh(host='example.pwnme',
            ...         user='demouser',
            ...         password='demopass')
            >>> cwd = s.set_working_directory()
            >>> s.ls()
            ''
            >>> s.pwd() == cwd
            True
        """
        status = 0

        if not wd:
            wd, status = self.run_to_end('x=$(mktemp -d) && cd $x && chmod +x . && echo $PWD', wd='.')
            wd = wd.strip()

            if status:
                log.error("Could not generate a temporary directory (%i)\n%s" % (status, wd))

        else:
            _, status = self.run_to_end('ls ' + misc.sh_string(wd), wd = '.')

            if status:
                log.error("%r does not appear to exist" % wd)

        log.info("Working directory: %r" % wd)
        self.cwd = wd
        return self.cwd
