import os, time, tempfile, sys, shutil, re, logging, threading

from .. import term
from ..context import context
from ..util import hashes, misc, safeeval
from .sock import sock
from .process import process
from ..timeout import Timeout
from ..log import getLogger, Logger

# Kill the warning line:
# No handlers could be found for logger "paramiko.transport"
paramiko_log = logging.getLogger("paramiko.transport")
h = logging.StreamHandler(file('/dev/null','w+'))
h.setFormatter(logging.Formatter())
paramiko_log.addHandler(h)

class ssh_channel(sock):
    def __init__(self, parent, process = None, tty = False, wd = None, env = None, timeout = Timeout.default, level = None):
        super(ssh_channel, self).__init__(timeout, level=level)

        # keep the parent from being garbage collected in some cases
        self.parent = parent

        self.returncode = None
        self.host = parent.host
        self.tty  = tty

        env = env or {}

        msg = 'Opening new channel: %r' % ((process,) or 'shell')
        with self.waitfor(msg) as h:
            if isinstance(process, (list, tuple)):
                process = ' '.join(misc.sh_string(s) for s in process)

            if process and wd:
                process = "cd %s 2>/dev/null >/dev/null; %s" % (misc.sh_string(wd), process)

            if process and env:
                for name, value in env.items():
                    if not re.match('^[a-zA-Z_][a-zA-Z0-9_]*$', name):
                        self.error('run(): Invalid environment key $r' % name)
                    process = '%s=%s %s' % (name, misc.sh_string(value), process)

            if process and tty:
                process = 'stty raw; ' + process

            self.sock = parent.transport.open_session()
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

    def recvall(self):
        # We subclass tubes.sock which sets self.sock to None.
        #
        # However, we need to wait for the return value to propagate,
        # which may not happen by the time .close() is called by tube.recvall()
        tmp_sock = self.sock

        data = super(ssh_channel, self).recvall()

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

        if self.returncode == None:
            if self.sock and (block or self.sock.exit_status_ready()):
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

        if not self.tty:
            return super(ssh_channel, self).interactive(prompt)

        self.info('Switching to interactive mode')

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
    def __init__(self, user, host, port = 22, password = None, key = None,
                 keyfile = None, proxy_command = None, proxy_sock = None,
                 timeout = Timeout.default, level = None, cache = True):
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

        NOTE: The proxy_command and proxy_sock arguments is only available if a
        fairly new version of paramiko is used."""
        super(ssh, self).__init__(timeout)

        Logger.__init__(self)
        if level is not None:
            self.setLevel(level)


        self.host            = host
        self.port            = port
        self._cachedir       = os.path.join(tempfile.gettempdir(), 'binjitsu-ssh-cache')
        self.cwd             = None
        self.cache           = cache

        misc.mkdir_p(self._cachedir)

        keyfiles = [os.path.expanduser(keyfile)] if keyfile else []

        import paramiko

        # Make a basic attempt to parse the ssh_config file
        try:
            ssh_config = paramiko.SSHConfig()
            ssh_config.parse(file(os.path.expanduser('~/.ssh/config')))
            host_config = ssh_config.lookup(host)
            if 'hostname' in host_config:
                self.host = host = host_config['hostname']
            if not keyfile and 'identityfile' in host_config:
                keyfile = host_cofig['identityfile'][0]
        except Exception:
            pass


        msg = 'Connecting to %s on port %d' % (host, port)
        with self.waitfor(msg) as h:
            self.client = paramiko.SSHClient()

            class IgnorePolicy(paramiko.MissingHostKeyPolicy):
                """Policy for what happens when an unknown ssh-fingerprint is encountered"""
                def __init__(self):
                    self.do_warning = False

            self.client.set_missing_host_key_policy(IgnorePolicy())

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

            h.success()

        try:
            self.sftp = self.transport.open_sftp_client()
        except Exception:
            self.sftp = None

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

    def process(self, args=[], executable=None, tty = True, cwd = None, env = None, timeout = Timeout.default, run = True):
        r"""
        Executes a process on the remote server, in the same fashion
        as pwnlib.tubes.process.process.

        Returns:
            A new SSH channel, or a path to the script if ``run=False``.

        Notes:
            Requires Python on the remote server.

        Examples:
            >>> s = ssh(host='localhost',
            ...         user='demouser',
            ...         password='demopass')
            >>> sh = s.process('sh')
            >>> sh.sendline('echo Hello; exit')
            >>> sh.recvall()
            'Hello\n'
            >>> s.process(['/bin/echo', '\xff']).recvall()
            '\xff\n'
            >>> s.process(['readlink', '/proc/self/exe']).recvall()
            '/bin/readlink\n'
            >>> s.process(['LOLOLOL', '/proc/self/exe'], executable='readlink').recvall()
            '/bin/readlink\n'
            >>> s.process(['LOLOLOL', '/proc/self/cmdline'], executable='cat').recvall()
            'LOLOLOL\x00/proc/self/cmdline\x00'
        """
        if not args and not executable:
            self.error("Must specify args or executable")

        if isinstance(args, (str, unicode)):
            args = [args]

        executable = executable or args[0]

        script = r"""
#!/usr/bin/env python
import os, sys
exe   = %r
args  = %r
env   = %r

if env is None:
    env = os.environ

def is_exe(path):
    if os.path.isfile(path) and os.access(path, os.X_OK):
        return 1
    return 0

if os.path.sep not in exe and not is_exe(exe):
    for path in os.environ['PATH'].split(os.pathsep):
        test_path = os.path.join(path, exe)
        if is_exe(test_path):
            exe = test_path
            break

can_execve = is_exe(exe)

if sys.argv[-1] == 'check':
    sys.stdout.write(str(can_execve) + "\n")
    sys.stdout.flush()

if can_execve:
    os.execve(exe, args, env)
""" % (executable, args, env)

        script = script.lstrip()

        execve_repr = "execve(%s, %s, %s)" % (executable, args, env or 'os.environ')

        with self.progress('Opening new channel: %s' % execve_repr) as h:
            self.debug("Executing binary with script:\n" + script)

            with context.local(log_level='error'):
                tmpfile = self.mktemp('-t', 'pwnlib-execve-XXXXXXXXXX')
                self.upload_data(script, tmpfile)
                self.chmod('+x', tmpfile)

                if not run:
                    return tmpfile

                python = self.run('test -x "$(which python 2>&1)" && exec python %s check; echo 2' % tmpfile)

            result = safeeval.const(python.recvline())

            if result == 0:
                self.error("%r does not exist or is not executable" % executable)
            elif result == 2:
                self.error("python is not installed on the remote system %r" % self.host)
            elif result != 1:
                h.failure()

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

        return ssh_channel(self, process, tty, wd, env, timeout, level = self.level)

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

        return ssh_connecter(self, host, port, timeout, level=self.level)

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

        return ssh_listener(self, bind_address, port, timeout, level=self.level)

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
            'download',             # frequent typo
            'upload',               # frequent typo
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
            self.info("Closed connection to %r" % self.host)

    def _libs_remote(self, remote):
        """Return a dictionary of the libraries used by a remote file."""
        cmd = '(ulimit -s unlimited; ldd %s > /dev/null && (LD_TRACE_LOADED_OBJECTS=1 %s || ldd %s)) 2>/dev/null'
        arg = misc.sh_string(remote)
        data, status = self.run_to_end(cmd % (arg, arg, arg))
        if status != 0:
            self.failure('Unable to find libraries for %r' % remote)
            return {}

        return misc.parse_ldd_output(data)

    def _get_fingerprint(self, remote):
        arg = misc.sh_string(remote)
        cmd = '(sha256sum %s||sha1sum %s||md5sum %s||shasum %s) 2>/dev/null' % (arg, arg, arg, arg)
        data, status = self.run_to_end(cmd)
        if status == 0:
            return data.split()[0]
        else:
            return None

    def _get_cachefile(self, fingerprint):
        return os.path.join(self._cachedir, fingerprint)

    def _verify_local_fingerprint(self, fingerprint):
        if not isinstance(fingerprint, str) or \
           len(fingerprint) not in [32, 40, 64] or \
           not set(fingerprint).issubset('abcdef0123456789'):
            self.failure('Invalid fingerprint %r' % fingerprint)
            return False

        local = self._get_cachefile(fingerprint)
        if not os.path.isfile(local):
            return False

        func = {32: hashes.md5filehex, 40: hashes.sha1filehex, 64: hashes.sha256filehex}[len(fingerprint)]

        if func(local) == fingerprint:
            return True
        else:
            os.unlink(local)
            return False

    def _download_raw(self, remote, local):
        with self.waitfor('Downloading %r' % remote) as h:

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

    def _download_to_cache(self, remote):
        fingerprint = self._get_fingerprint(remote)
        if fingerprint == None:
            local = os.path.normpath(remote)
            local = os.path.basename(local)
            local += time.strftime('-%Y-%m-%d-%H:%M:%S')
            local = os.path.join(self._cachedir, local)

            self._download_raw(remote, local)
            return local

        local = self._get_cachefile(fingerprint)

        if self.cache and self._verify_local_fingerprint(fingerprint):
            self.success('Found %r in ssh cache' % remote)
        else:
            self._download_raw(remote, local)

            if not self._verify_local_fingerprint(fingerprint):
                self.error('Could not download file %r' % remote)

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
        with open(self._download_to_cache(remote)) as fd:
            return fd.read()

    def download_file(self, remote, local = None):
        """Downloads a file from the remote server.

        The file is cached in /tmp/binjitsu-ssh-cache using a hash of the file, so
        calling the function twice has little overhead.

        Arguments:
          remote(str): The remote filename to download
          local(str): The local filename to save it to. Default is to infer it from the remote filename."""

        if not local:
            local = os.path.basename(os.path.normpath(remote))

        if self.cwd and os.path.basename(remote) == remote:
            remote = os.path.join(self.cwd, remote)

        local_tmp = self._download_to_cache(remote)
        shutil.copy2(local_tmp, local)

    def download_dir(self, local, remote=None):
        """Recursively uploads a directory onto the remote server

        Arguments:
            local: Local directory
            remote: Remote directory
        """
        remote   = remote or '.'

        localcwd = os.path.dirname(local) or self.cwd
        local    = os.path.basename(local)

        self.info("Downloading %r to %r" % (local,remote))

        source = self.run(['sh', '-c', 'tar -C %s -czf- %s' % (localcwd, local)])
        sink   = process(['sh', '-c', 'tar -C %s -xzf-' % remote])

        source >> sink

        sink.wait_for_close()

    def upload_data(self, data, remote):
        """Uploads some data into a file on the remote server.

        Arguments:
          data(str): The data to upload.
          remote(str): The filename to upload it to.

        Examoles:
            >>> s =  ssh(host='example.pwnme',
            ...         user='demouser',
            ...         password='demopass')
            >>> s.upload_data('Hello, world', '/tmp/foo')
            >>> print file('/tmp/foo').read()
            Hello, world
            >>> s.sftp = False
            >>> s.upload_data('Hello, world', '/tmp/bar')
            >>> print file('/tmp/bar').read()
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
            s = self.run('cat>' + misc.sh_string(remote))
            s.send(data)
            s.shutdown('send')
            s.recvall()
            if s.wait() != 0:
                self.error("Could not upload file %r" % remote)

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

        self.info("Uploading %r to %r" % (filename,remote))
        self.upload_data(data, remote)

        return remote

    def upload_dir(self, local, remote=None):
        """Recursively uploads a directory onto the remote server

        Arguments:
            local: Local directory
            remote: Remote directory
        """
        remote   = remote or self.cwd

        localcwd = os.path.dirname(local)
        local    = os.path.basename(local)

        self.info("Uploading %r to %r" % (local,remote))

        source  = process(['sh', '-c', 'tar -C %s -czf- %s' % (localcwd, local)])
        sink    = self.run(['sh', '-c', 'tar -C %s -xzf-' % remote])

        source <> sink

        sink.wait_for_close()

    def libs(self, remote, directory = None):
        """Downloads the libraries referred to by a file.

        This is done by running ldd on the remote server, parsing the output
        and downloading the relevant files.

        The directory argument specified where to download the files. This defaults
        to './$HOSTNAME' where $HOSTNAME is the hostname of the remote server."""

        libs = self._libs_remote(remote)

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

        if self.cwd:
            s.sendline('cd ' + misc.sh_string(self.cwd))

        s.interactive()
        s.close()

    def set_working_directory(self, wd = None):
        """Sets the working directory in which future commands will
        be run (via ssh.run) and to which files will be uploaded/downloaded
        from if no path is provided

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
            wd, status = self.run_to_end('x=$(mktemp -d); chmod +x $x; echo $x', wd = None)
            wd = wd.strip()

        if status:
            self.failure("Could not generate a temporary directory\n%s" % wd)
            return

        _, status = self.run_to_end('ls ' + misc.sh_string(wd), wd = None)

        if status:
            self.failure("%r does not appear to exist" % wd)
            return

        self.info("Working directory: %r" % wd)
        self.cwd = wd
        return self.cwd
