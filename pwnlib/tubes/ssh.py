import inspect
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
import types

from .. import term
from ..context import context
from ..log import Logger
from ..log import getLogger
from ..timeout import Timeout
from ..util import hashes
from ..util import misc
from ..util import safeeval
from ..util import sh_string
from .process import process
from .sock import sock

# Kill the warning line:
# No handlers could be found for logger "paramiko.transport"
paramiko_log = logging.getLogger("paramiko.transport")
h = logging.StreamHandler(file('/dev/null','w+'))
h.setFormatter(logging.Formatter())
paramiko_log.addHandler(h)

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
    executable = None

    #: Arguments passed to the process
    #: Only valid when instantiated through :meth:`ssh.process`
    argv = None

    def __init__(self, parent, process = None, tty = False, wd = None, env = None, timeout = Timeout.default, level = 0, raw = True):
        super(ssh_channel, self).__init__(timeout, level=level)

        # keep the parent from being garbage collected in some cases
        self.parent = parent

        self.returncode = None
        self.host = parent.host
        self.tty  = tty
        self.env  = env
        self.process = process
        self.cwd  = wd or '.'

        env = env or {}
        msg = 'Opening new channel: %r' % (process or 'shell')

        if isinstance(process, (list, tuple)):
            fmt = ' '.join('%s' for s in process)
            process = sh_string.sh_command_with(fmt, *process)

        if process and wd:
            process = sh_string.sh_command_with('cd %s >/dev/null 2>&1;', wd) + process

        if process and env:
            for name, value in env.items():
                if not re.match('^[a-zA-Z_][a-zA-Z0-9_]*$', name):
                    self.error('run(): Invalid environment key $r' % name)
                process = '%s;%s' % (sh_string.sh_prepare(name, value, export=True), process)

        if process and tty:
            if raw:
                process = 'stty raw -ctlecho -echo; ' + process
            else:
                process = 'stty -ctlecho -echo; ' + process


        # If this object is enabled for DEBUG-level logging, don't hide
        # anything about the command that's actually executed.
        if process and self.isEnabledFor(logging.DEBUG):
            msg = 'Opening new channel: %r' % ((process,) or 'shell')

        with self.waitfor(msg) as h:
            import paramiko
            try:
                self.sock = parent.transport.open_session()
            except paramiko.ChannelException as e:
                if e.args == (1, 'Administratively prohibited'):
                    self.error("Too many sessions open! Use ssh_channel.close() or 'with'!")
                raise e

            if self.tty:
                self.sock.get_pty('xterm', term.width, term.height)

                def resizer():
                    if self.sock:
                        try:
                            self.sock.resize_pty(term.width, term.height)
                        except paramiko.ssh_exception.SSHException:
                            pass

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

        if self.returncode == None and self.sock \
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

        self.info('Switching to interactive mode')

        # We would like a cursor, please!
        term.term.show_cursor()

        event = threading.Event()
        def recv_thread(event):
            while not event.is_set():
                try:
                    cur = self.recv(timeout = 0.05)
                    cur = cur.replace('\r\n','\n')
                    cur = cur.replace('\r','')
                    if cur == None:
                        continue
                    elif cur == '\a':
                        # Ugly hack until term unstands bell characters
                        continue
                    sys.stdout.write(cur)
                    sys.stdout.flush()
                except EOFError:
                    self.info('Got EOF while reading in interactive')
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
                    self.info('Got EOF while sending in interactive')

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
        self.error("Cannot use spawn_process on an SSH channel.""")

    def _close_msg(self):
        self.info('Closed SSH channel with %s' % self.host)

    def getenv(self, variable, **kwargs):
        """Retrieve the address of an environment variable in the remote process.
        """
        if not hasattr(self, 'argv'):
            log.error("Can only call getenv() on ssh_channel objects created with ssh.process")

        argv0 = self.argv[0]

        script = ';'.join(('from ctypes import *',
                           'import os',
                           'libc = CDLL("libc.so.6")',
                           'print os.path.realpath(%r)' % self.executable,
                           'print(libc.getenv(%r))' % variable,))

        try:
            with context.local(log_level='error'):
                python = self.parent.which('python')

                if not python:
                    self.error("Python is not installed on the remote system.")

                io = self.parent.process([argv0,'-c', script.strip()],
                                          executable=python,
                                          env=self.env,
                                          **kwargs)
                path = io.recvline()
                address = int(io.recvline())

                address -= len(python)
                address += len(path)

                return int(address) & context.mask
        except:
            self.exception("Could not look up environment variable %r" % variable)

    def libs(self):
        """libs() -> dict

        Returns a dictionary mapping the address of each loaded library in the
        process's address space.

        If ``/proc/$PID/maps`` cannot be opened, the output of ldd is used
        verbatim, which may be different than the actual addresses if ASLR
        is enabled.
        """
        if not self.executable:
            self.error("Can only use libs() on ssh_channel objects created with ssh.process()")

        maps = self.parent.libs(self.executable)

        maps_raw = self.parent.cat('/proc/%d/maps' % self.pid)

        for lib in maps:
            remote_path = lib.split(self.parent.host)[-1]
            for line in maps_raw.splitlines():
                if line.endswith(remote_path):
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

class ssh_connecter(sock):
    def __init__(self, parent, host, port, timeout = Timeout.default, level = None):
        super(ssh_connecter, self).__init__(timeout, level = level)

        # keep the parent from being garbage collected in some cases
        self.parent = parent

        self.host  = parent.host
        self.rhost = host
        self.rport = port

        msg = 'Connecting to %s:%d via SSH to %s' % (self.rhost, self.rport, self.host)
        with self.waitfor(msg) as h:
            try:
                self.sock = parent.transport.open_channel('direct-tcpip', (host, port), ('127.0.0.1', 0))
            except Exception as e:
                self.exception(e.message)
                raise

            sockname = self.sock.get_transport().sock.getsockname()
            self.lhost = sockname[0]
            self.lport = sockname[1]

            h.success()

    def spawn_process(self, *args, **kwargs):
        self.error("Cannot use spawn_process on an SSH channel.""")

    def _close_msg(self):
        self.info("Closed remote connection to %s:%d via SSH connection to %s" % (self.rhost, self.rport, self.host))


class ssh_listener(sock):
    def __init__(self, parent, bind_address, port, timeout = Timeout.default, level = None):
        super(ssh_listener, self).__init__(timeout, level = level)

        # keep the parent from being garbage collected in some cases
        self.parent = parent

        self.host = parent.host

        try:
            self.port = parent.transport.request_port_forward(bind_address, port)

        except Exception:
            h.failure('Failed create a port forwarding')
            raise

        def accepter():
            msg = 'Waiting on port %d via SSH to %s' % (self.port, self.host)
            h   = self.waitfor(msg)
            try:
                self.sock = parent.transport.accept()
                parent.transport.cancel_port_forward(bind_address, self.port)
            except Exception:
                self.sock = None
                h.failure()
                self.exception('Failed to get a connection')
                return

            self.rhost, self.rport = self.sock.origin_addr
            h.success('Got connection from %s:%d' % (self.rhost, self.rport))

        self._accepter = context.Thread(target = accepter)
        self._accepter.daemon = True
        self._accepter.start()

    def _close_msg(self):
        self.info("Closed remote connection to %s:%d via SSH listener on port %d via %s" % (self.rhost, self.rport, self.port, self.host))

    def spawn_process(self, *args, **kwargs):
        self.error("Cannot use spawn_process on an SSH channel.""")

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


class ssh(Timeout, Logger):

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
                 timeout = Timeout.default, level = None, cache = True,
                 ssh_agent = False):
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
            level: Log level
            cache: Cache downloaded files (by hash/size/timestamp)
            ssh_agent: If ``True``, enable usage of keys via ssh-agent

        NOTE: The proxy_command and proxy_sock arguments is only available if a
        fairly new version of paramiko is used."""
        super(ssh, self).__init__(timeout)

        Logger.__init__(self)
        if level is not None:
            self.setLevel(level)


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

        # This is a dirty hack to make my Yubikey shut up.
        # If anybody has a problem with this, please open a bug and I'll
        # figure out a better workaround.
        if not ssh_agent:
            os.environ.pop('SSH_AUTH_SOCK', None)

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
                    if keyfile.lower() == 'none':
                        keyfile = None
        except Exception as e:
            self.debug("An error occurred while parsing ~/.ssh/config:\n%s" % e)

        keyfiles = [os.path.expanduser(keyfile)] if keyfile else []

        msg = 'Connecting to %s on port %d' % (host, port)
        with self.waitfor(msg) as h:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            known_hosts = os.path.expanduser('~/.ssh/known_hosts')
            if os.path.exists(known_hosts):
                self.client.load_host_keys(known_hosts)

            has_proxy = (proxy_sock or proxy_command) and True
            if has_proxy:
                if 'ProxyCommand' not in dir(paramiko):
                    self.error('This version of paramiko does not support proxies.')

                if proxy_sock and proxy_command:
                    self.error('Cannot have both a proxy command and a proxy sock')

                if proxy_command:
                    proxy_sock = paramiko.ProxyCommand(proxy_command)
                self.client.connect(host, port, user, password, key, keyfiles, self.timeout, compress = True, sock = proxy_sock)
            else:
                self.client.connect(host, port, user, password, key, keyfiles, self.timeout, compress = True)

            self.transport = self.client.get_transport()
            self.transport.use_compression(True)

            h.success()

        self._tried_sftp = False

        with context.local(log_level='error'):
            try:
                self.pid = int(self.system('echo $PPID').recv(timeout=1))
            except Exception:
                self.pid = None

    @property
    def sftp(self):
        if not self._tried_sftp:
            try:
                self._sftp = self.transport.open_sftp_client()
            except Exception:
                self._sftp = None

        self._tried_sftp = True
        return self._sftp


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
            ...         user='travis',
            ...         password='demopass')
            >>> sh = s.shell('/bin/sh')
            >>> sh.sendline('echo Hello; exit')
            >>> print 'Hello' in sh.recvall()
            True
        """
        return self.run(shell, tty, timeout = timeout)

    def process(self, argv=None, executable=None, tty=True, cwd=None, env=None, timeout=Timeout.default, run=True,
                stdin=0, stdout=1, stderr=2, preexec_fn=None, preexec_args=[], raw=True, aslr=None, setuid=None):
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
            preexec_fn(callable):
                Function which is executed on the remote side before execve().
            preexec_args(object):
                Argument passed to ``preexec_fn``.
            raw(bool):
                If ``True``, disable TTY control code interpretation.
            aslr(bool):
                See ``pwnlib.tubes.process.process`` for more information.
            setuid(bool):
                See ``pwnlib.tubes.process.process`` for more information.

        Returns:
            A new SSH channel, or a path to a script if ``run=False``.

        Notes:
            Requires Python on the remote server.

        Examples:
            >>> s = ssh(host='example.pwnme',
            ...         user='travis',
            ...         password='demopass')
            >>> sh = s.process('/bin/sh', env={'PS1':''})
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
            >>> sh.pid in pidof('sh') # doctest: +SKIP
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
            >>> s.process(['/usr/bin/env'], env={}).recvall()
            ''
            >>> s.process('/usr/bin/env', env={'A':'B'}).recvall()
            'A=B\n'
        """
        if not argv and not executable:
            self.error("Must specify argv or executable")

        argv      = argv or []
        aslr      = aslr if aslr is not None else context.aslr

        if isinstance(argv, (str, unicode)):
            argv = [argv]

        if not isinstance(argv, (list, tuple)):
            self.error('argv must be a list or tuple')

        # Python doesn't like when an arg in argv contains '\x00'
        # -> execve() arg 2 must contain only strings
        for i, arg in enumerate(argv):
            if '\x00' in arg[:-1]:
                self.error('Inappropriate nulls in argv[%i]: %r' % (i, arg))
            argv[i] = arg.rstrip('\x00')

        # Python also doesn't like when envp contains '\x00'
        if env and hasattr(env, 'items'):
            for k, v in env.items():
                if '\x00' in k[:-1]:
                    self.error('Inappropriate nulls in environment key %r' % (i, k))
                if '\x00' in v[:-1]:
                    self.error('Inappropriate nulls in environment value %r=%r' % (k, v))
                env[k.rstrip('\x00')] = v.rstrip('\x00')

        executable = executable or argv[0]
        cwd        = cwd or self.cwd

        # Validate, since failures on the remote side will suck.
        if not isinstance(executable, str):
            self.error("executable / argv[0] must be a string: %r" % executable)
        if not isinstance(argv, (list, tuple)):
            self.error("argv must be a list or tuple: %r" % argv)
        if env is not None and not isinstance(env, dict) and env != os.environ:
            self.error("env must be a dict: %r" % env)
        if not all(isinstance(s, str) for s in argv):
            self.error("argv must only contain strings: %r" % argv)

        # Allow passing in sys.stdin/stdout/stderr objects
        handles = {sys.stdin: 0, sys.stdout:1, sys.stderr:2}
        stdin  = handles.get(stdin, stdin)
        stdout = handles.get(stdout, stdout)
        stderr = handles.get(stderr, stderr)

        # Allow the user to provide a self-contained function to run
        def func(): pass
        func      = preexec_fn or func
        func_src  = inspect.getsource(func).strip()
        func_name = func.__name__
        func_args = preexec_args

        if not isinstance(func, types.FunctionType):
            log.error("preexec_fn must be a function")
        if func_name == (lambda: 0).__name__:
            log.error("preexec_fn cannot be a lambda")

        setuid = setuid if setuid is None else bool(setuid)

        script = r"""
#!/usr/bin/env python2
import os, sys, ctypes, resource, platform
from collections import OrderedDict
exe   = %(executable)r
argv  = %(argv)r
env   = %(env)r

os.chdir(%(cwd)r)

if env is not None:
    os.environ.clear()
    os.environ.update(env)

def is_exe(path):
    return os.path.isfile(path) and os.access(path, os.X_OK)

PATH = os.environ.get('PATH','').split(os.pathsep)

if os.path.sep not in exe and not is_exe(exe):
    for path in PATH:
        test_path = os.path.join(path, exe)
        if is_exe(test_path):
            exe = test_path
            break

if not is_exe(exe):
    sys.stderr.write('3\n')
    sys.stderr.write("{} is not executable or does not exist in $PATH: {}".format(exe,PATH))
    sys.exit(-1)

if %(setuid)r is False:
    PR_SET_NO_NEW_PRIVS = 38
    result = ctypes.CDLL('libc.so.6').prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)

    if result != 0:
        sys.stdout.write('3\n')
        sys.stdout.write("Could not disable setuid: prctl(PR_SET_NO_NEW_PRIVS) failed")
        sys.exit(-1)

if sys.argv[-1] == 'check':
    sys.stdout.write("1\n")
    sys.stdout.write(str(os.getpid()) + "\n")
    sys.stdout.write(exe + '\x00')
    sys.stdout.flush()

for fd, newfd in {0: %(stdin)r, 1: %(stdout)r, 2:%(stderr)r}.items():
    if newfd is None:
        close(fd)
    elif isinstance(newfd, str):
        os.close(fd)
        os.open(newfd, os.O_RDONLY if fd == 0 else (os.O_RDWR|os.O_CREAT))
    elif isinstance(newfd, int) and newfd != fd:
        os.dup2(fd, newfd)

if not %(aslr)r:
    if platform.system().lower() == 'linux' and %(setuid)r is not True:
        ADDR_NO_RANDOMIZE = 0x0040000
        ctypes.CDLL('libc.so.6').personality(ADDR_NO_RANDOMIZE)

    resource.setrlimit(resource.RLIMIT_STACK, (-1, -1))

# Assume that the user would prefer to have core dumps.
resource.setrlimit(resource.RLIMIT_CORE, (-1, -1))

%(func_src)s
apply(%(func_name)s, %(func_args)r)

os.execve(exe, argv, os.environ)
""" % locals()

        script = script.strip()

        self.debug("Created execve script:\n" + script)

        if not run:
            with context.local(log_level='error'):
                tmpfile = self.mktemp('-t', 'pwnlib-execve-XXXXXXXXXX')
                self.chmod('+x', tmpfile)

            self.info("Uploading execve script to %r" % tmpfile)
            self.upload_data(script, tmpfile)
            return tmpfile

        execve_repr = "execve(%r, %s, %s)" % (executable,
                                              argv,
                                              'os.environ'
                                              if (env in (None, os.environ))
                                              else env)

        # Avoid spamming the screen
        if context.log_level >= logging.INFO and len(execve_repr) > 512:
            execve_repr = execve_repr[:512] + '...'

        with self.progress('Opening new channel: %s' % execve_repr) as h:

            if not aslr:
                self.warn_once("ASLR is disabled!")

            script = sh_string.sh_command_with('for py in python2.7 python2 python; do test -x "$(which $py 2>&1)" && exec $py -c %s check; done; echo 2', script)
            with context.local(log_level='error'):
                python = self.run(script, raw=raw)
            result = safeeval.const(python.recvline())

            # If an error occurred, try to grab as much output
            # as we can.
            if result != 1:
                error_message = python.recvrepeat(timeout=1)

            if result == 0:
                self.error("%r does not exist or is not executable" % executable)
            elif result == 3:
                self.error(error_message)
            elif result == 2:
                self.error("python is not installed on the remote system %r" % self.host)
            elif result != 1:
                h.failure("something bad happened:\n%s" % error_message)

            python.pid  = safeeval.const(python.recvline())
            python.argv = argv
            python.executable = python.recvuntil('\x00')[:-1]

        return python

    def which(self, program):
        """which(program) -> str

        Minor modification to just directly invoking ``which`` on the remote
        system which adds the current working directory to the end of ``$PATH``.
        """
        # If name is a path, do not attempt to resolve it.
        if os.path.sep in program:
            return program

        result = self.run('export PATH=$PATH:$PWD; which %s' % program).recvall().strip()

        if '/' not in result:
            return None

        return result

    def system(self, process, tty = True, wd = None, env = None, timeout = Timeout.default, raw = True):
        r"""system(process, tty = True, wd = None, env = None, timeout = Timeout.default, raw = True) -> ssh_channel

        Open a new channel with a specific process inside. If `tty` is True,
        then a TTY is requested on the remote server.

        If `raw` is True, terminal control codes are ignored and input is not
        echoed back.

        Return a :class:`pwnlib.tubes.ssh.ssh_channel` object.

        Examples:
            >>> s =  ssh(host='example.pwnme',
            ...         user='travis',
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

        return ssh_channel(self, process, tty, wd, env, timeout, level = self.level, raw = raw)

    #: Backward compatibility.  Use :meth:`system`
    run = system

    def getenv(self, variable, **kwargs):
        """Retrieve the address of an environment variable on the remote
        system.

        Note:

            The exact address will differ based on what other environment
            variables are set, as well as argv[0].  In order to ensure that
            the path is *exactly* the same, it is recommended to invoke the
            process with ``argv=[]``.

        Example:

            >>> s =  ssh(host='example.pwnme',
            ...         user='travis',
            ...         password='demopass',
            ...         cache=False)
            >>>

        """
        script = '''
from ctypes import *; libc = CDLL('libc.so.6'); print(libc.getenv(%r))
''' % variable

        with context.local(log_level='error'):
            python = self.which('python')

            if not python:
                self.error("Python is not installed on the remote system.")

            io = self.process(['','-c', script.strip()], executable=python, **kwargs)
            result = io.recvall()

        try:
            return int(result) & context.mask
        except:
            self.exception("Could not look up environment variable %r" % variable)



    def run_to_end(self, process, tty = False, wd = None, env = None):
        r"""run_to_end(process, tty = False, timeout = Timeout.default, env = None) -> str

        Run a command on the remote server and return a tuple with
        (data, exit_status). If `tty` is True, then the command is run inside
        a TTY on the remote server.

        Examples:
            >>> s =  ssh(host='example.pwnme',
            ...         user='travis',
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
            ...         user='travis',
            ...         password='demopass')
            >>> a = s.connect_remote(s.host, l.lport)
            >>> b = l.wait_for_connection()
            >>> a.sendline('Hello')
            >>> print repr(b.recvline())
            'Hello\n'
        """

        return ssh_connecter(self, host, port, timeout, level=self.level)

    remote = connect_remote

    def listen_remote(self, port = 0, bind_address = '', timeout = Timeout.default):
        r"""listen_remote(port = 0, bind_address = '', timeout = Timeout.default) -> ssh_connecter

        Listens remotely through an SSH connection. This is equivalent to
        using the ``-R`` flag on ``ssh``.

        Returns a :class:`pwnlib.tubes.ssh.ssh_listener` object.

        Examples:

            >>> from pwn import *
            >>> s =  ssh(host='example.pwnme',
            ...         user='travis',
            ...         password='demopass')
            >>> l = s.listen_remote()
            >>> a = remote(s.host, l.port)
            >>> b = l.wait_for_connection()
            >>> a.sendline('Hello')
            >>> print repr(b.recvline())
            'Hello\n'
        """

        return ssh_listener(self, bind_address, port, timeout, level=self.level)

    listen = listen_remote

    def __getitem__(self, attr):
        """Permits indexed access to run commands over SSH

        Examples:

            >>> s =  ssh(host='example.pwnme',
            ...         user='travis',
            ...         password='demopass')
            >>> print s['echo hello']
            hello
        """
        return self.__getattr__(attr)()

    def __call__(self, attr):
        """Permits function-style access to run commands over SSH

        Examples:

            >>> s =  ssh(host='example.pwnme',
            ...         user='travis',
            ...         password='demopass')
            >>> print repr(s('echo hello'))
            'hello'
        """
        return self.__getattr__(attr)()

    def __getattr__(self, attr):
        """Permits member access to run commands over SSH

        Examples:

            >>> s =  ssh(host='example.pwnme',
            ...         user='travis',
            ...         password='demopass')
            >>> s.echo('hello')
            'hello'
            >>> s.whoami()
            'travis'
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
            ...         user='travis',
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
            self.info("Closed connection to %r" % self.host)

    def _libs_remote(self, remote):
        """Return a dictionary of the libraries used by a remote file."""
        cmd = '(ulimit -s unlimited; ldd %s > /dev/null && (LD_TRACE_LOADED_OBJECTS=1 %s || ldd %s)) 2>/dev/null'
        cmd = sh_string.sh_command_with(lambda arg: cmd % (arg, arg, arg), remote)
        data, status = self.run_to_end(cmd)
        if status != 0:
            self.error('Unable to find libraries for %r' % remote)
            return {}

        return misc.parse_ldd_output(data)

    def _get_fingerprint(self, remote):
        cmd = '(openssl sha256 || sha256 || sha256sum) 2>/dev/null < %s'
        cmd = sh_string.sh_command_with(cmd, remote)
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
            self.error('Invalid fingerprint %r' % fingerprint)
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

        cmd = sh_string.sh_command_with('wc -c < %s', remote)
        total, exitcode = self.run_to_end(cmd)

        if exitcode != 0:
            h.failure("%r does not exist or is not accessible" % remote)
            return

        total = int(total)

        with context.local(log_level = 'ERROR'):
            cmd = sh_string.sh_command_with('cat < %s', remote)
            c = self.run(cmd)
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
            ...         user='travis',
            ...         password='demopass',
            ...         cache=False)
            >>> s.download_data('/tmp/bar')
            'Hello, world'
            >>> s._sftp = None
            >>> s._tried_sftp = True
            >>> s.download_data('/tmp/bar')
            'Hello, world'

        """
        with self.progress('Downloading %r' % remote) as p:
            with open(self._download_to_cache(remote, p)) as fd:
                return fd.read()

    def download_file(self, remote, local = None):
        """Downloads a file from the remote server.

        The file is cached in /tmp/pwntools-ssh-cache using a hash of the file, so
        calling the function twice has little overhead.

        Arguments:
            remote(str): The remote filename to download
            local(str): The local filename to save it to. Default is to infer it from the remote filename.
        """


        if not local:
            local = os.path.basename(os.path.normpath(remote))

        if os.path.basename(remote) == remote:
            remote = os.path.join(self.cwd, remote)

        with self.progress('Downloading %r to %r' % (remote, local)) as p:
            local_tmp = self._download_to_cache(remote, p)

        # Check to see if an identical copy of the file already exists
        if not os.path.exists(local) or hashes.sha256filehex(local_tmp) != hashes.sha256filehex(local):
            shutil.copy2(local_tmp, local)

    def download_dir(self, remote=None, local=None):
        """Recursively downloads a directory from the remote server

        Arguments:
            local: Local directory
            remote: Remote directory
        """
        remote   = remote or self.cwd


        if self.sftp:
            remote = str(self.sftp.normalize(remote))
        else:
            with context.local(log_level='error'):
                remote = self.system(sh_string.sh_command_with('readlink -f %s', remote))

        dirname  = os.path.dirname(remote)
        basename = os.path.basename(remote)

        local    = local or '.'
        local    = os.path.expanduser(local)

        self.info("Downloading %r to %r" % (basename,local))

        with context.local(log_level='error'):
            remote_tar = self.mktemp()
            tar = self.system(sh_string.sh_command_with('tar -C %s -czf %s %s', dirname, remote_tar, basename))

            if 0 != tar.wait():
                self.error("Could not create remote tar")

            local_tar = tempfile.NamedTemporaryFile(suffix='.tar.gz')
            self.download_file(remote_tar, local_tar.name)

            tar = tarfile.open(local_tar.name)
            tar.extractall(local)


    def upload_data(self, data, remote):
        """Uploads some data into a file on the remote server.

        Arguments:
            data(str): The data to upload.
            remote(str): The filename to upload it to.

        Example:
            >>> s =  ssh(host='example.pwnme',
            ...         user='travis',
            ...         password='demopass')
            >>> s.upload_data('Hello, world', '/tmp/upload_foo')
            >>> print file('/tmp/upload_foo').read()
            Hello, world
            >>> s._sftp = False
            >>> s._tried_sftp = True
            >>> s.upload_data('Hello, world', '/tmp/upload_bar')
            >>> print file('/tmp/upload_bar').read()
            Hello, world
        """
        # If a relative path was provided, prepend the cwd
        if os.path.normpath(remote) == os.path.basename(remote):
            remote = os.path.join(self.cwd, remote)

        if self.sftp:
            with tempfile.NamedTemporaryFile() as f:
                f.write(data)
                f.flush()
                self.sftp.put(f.name, remote)
                return

        with context.local(log_level = 'ERROR'):
            cmd = sh_string.sh_command_with('cat>%s', remote)
            s = self.run(cmd, tty=False)
            s.send(data)
            s.shutdown('send')
            data   = s.recvall()
            result = s.wait()
            if result != 0:
                self.error("Could not upload file %r (%r)\n%s" % (remote, result, data))

    def upload_file(self, filename, remote = None):
        """Uploads a file to the remote server. Returns the remote filename.

        Arguments:
        filename(str): The local filename to download
        remote(str): The remote filename to save it to. Default is to infer it from the local filename."""


        if remote == None:
            remote = os.path.normpath(filename)
            remote = os.path.basename(remote)
            remote = os.path.join(self.cwd, remote)

        with open(filename) as fd:
            data = fd.read()

        self.info("Uploading %r to %r" % (filename,remote))
        self.upload_data(data, remote)

        return remote

    def upload_dir(self, local, remote=None):
        """Recursively uploads a directory onto the remote server

        Arguments:
            local: Local directory
            remote: Remote directory
        """

        remote    = remote or self.cwd

        local     = os.path.expanduser(local)
        dirname   = os.path.dirname(local)
        basename  = os.path.basename(local)

        if not os.path.isdir(local):
            self.error("%r is not a directory" % local)

        msg = "Uploading %r to %r" % (basename,remote)
        with self.waitfor(msg) as w:
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
                    self.error("Could not untar %r on the remote end\n%s" % (remote_tar, message))

    def upload(self, file_or_directory, remote=None):
        if isinstance(file_or_directory, str):
            file_or_directory = os.path.expanduser(file_or_directory)
            file_or_directory = os.path.expandvars(file_or_directory)

        if os.path.isfile(file_or_directory):
            return self.upload_file(file_or_directory, remote)

        if os.path.isdir(file_or_directory):
            return self.upload_dir(file_or_directory, remote)

        log.error('%r does not exist' % file_or_directory)


    def download(self, file_or_directory, remote=None):
        if not self.sftp:
            self.error("Cannot determine remote file type without SFTP")

        if 0 == self.system(sh_string.sh_command_with('test -d %s', file_or_directory)).wait():
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
                self.warning('This seems fishy: %r' % lib)
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

        if self.cwd != '.':
            cmd = sh_string.sh_command_with('cd %s', self.cwd)
            s.sendline(cmd)

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
            ...         user='travis',
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
                self.error("Could not generate a temporary directory (%i)\n%s" % (status, wd))

        else:
            cmd = sh_string.sh_command_with('ls %s', wd)
            _, status = self.run_to_end(cmd, wd = '.')

            if status:
                self.error("%r does not appear to exist" % wd)

        self.info("Working directory: %r" % wd)
        self.cwd = wd
        return self.cwd

    def write(self, path, data):
        """Wrapper around upload_data to match ``pwnlib.util.misc.write``"""
        return self.upload_data(data, path)

    def read(self, path):
        """Wrapper around download_data to match ``pwnlib.util.misc.read``"""
        return self.download_data(path)
