import os, time, tempfile, sys, shutil, re, logging, threading

from .. import term
from ..context import context
from ..util import hashes, misc
from .sock import sock
from .process import process
from ..timeout import Timeout

log = logging.getLogger(__name__)

# Kill the warning line:
# No handlers could be found for logger "paramiko.transport"
paramiko_log = logging.getLogger("paramiko.transport")
h = logging.StreamHandler(file('/dev/null','w+'))
h.setFormatter(logging.Formatter())
paramiko_log.addHandler(h)

class ssh_channel(sock):
    def __init__(self, parent, process = None, tty = False, wd = None, env = None, timeout = Timeout.default):
        super(ssh_channel, self).__init__(timeout)

        # keep the parent from being garbage collected in some cases
        self.parent = parent

        self.returncode = None
        self.host = parent.host
        self.tty  = tty

        env = env or {}

        msg = 'Opening new channel: %r' % ((process,) or 'shell')
        with log.waitfor(msg) as h:
            if isinstance(process, (list, tuple)):
                process = ' '.join(misc.sh_string(s) for s in process)

            if process and wd:
                process = "cd %s 2>/dev/null >/dev/null; %s" % (misc.sh_string(wd), process)

            if process and env:
                for name, value in env.items():
                    if not re.match('^[a-zA-Z_][a-zA-Z0-9_]*$', name):
                        log.error('run(): Invalid environment key $r' % name)
                    process = '%s=%s %s' % (name, misc.sh_string(value), process)

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
            except:
                h.failure()
                raise

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
            h.failure('Failed create a port forwarding')
            raise

        def accepter():
            msg = 'Waiting on port %d via SSH to %s' % (self.port, self.host)
            h   = log.waitfor(msg)
            try:
                self.sock = parent.transport.accept()
                parent.transport.cancel_port_forward(bind_address, self.port)
            except:
                self.sock = None
                h.failure()
                log.exception('Failed to get a connection')
                return

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
    def __init__(self, user, host, port = 22, password = None, key = None, keyfile = None, proxy_command = None, proxy_sock = None, timeout = Timeout.default):
        """Creates a new ssh connection.

        Args:
          user(str): The username to log in with
          host(str): The hostname to connect to
          port(int): The port to connect to
          password(str): Try to authenticate using this password
          key(str): Try to authenticate using this private key. The string should be the actual private key.
          keyfile(str): Try to authenticate using this private key. The string should be a filename.
          proxy_command(str): Use this as a proxy command. It has approximately the same semantics as ProxyCommand from ssh(1).
          proxy_sock(str): Use this socket instead of connecting to the host.

        NOTE: The proxy_command and proxy_sock arguments is only available if a
        fairly new version of paramiko is used."""
        super(ssh, self).__init__(timeout)


        self.host            = host
        self.port            = port
        self._cachedir       = os.path.join(tempfile.gettempdir(), 'pwntools-ssh-cache')
        self._wd             = None
        misc.mkdir_p(self._cachedir)

        keyfiles = [os.path.expanduser(keyfile)] if keyfile else []

        msg = 'Connecting to %s on port %d' % (host, port)
        with log.waitfor(msg) as h:
            import paramiko
            self.client = paramiko.SSHClient()

            class IgnorePolicy(paramiko.MissingHostKeyPolicy):
                """Policy for what happens when an unknown ssh-fingerprint is encountered"""
                def __init__(self):
                    self.do_warning = False

            self.client.set_missing_host_key_policy(IgnorePolicy())

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

    def __enter__(self, *a):
        return self

    def __exit__(self, *a, **kw):
        self.close()

    def shell(self, shell = None, tty = True, timeout = Timeout.default):
        """shell(shell = None, tty = False, timeout = Timeout.default) -> ssh_channel

        Open a new channel with a shell inside.

        Arguments:
            shell(str): Path to the shell program to run.
                If ``None``, uses the default shell for the logged in user.
            tty(bool): If ``True``, then a TTY is requested on the remote server.

        Returns:
            Return a :class:`pwnlib.tubes.ssh.ssh_channel` object.

        Examples:
            >>> with ssh(host='localhost',
            ...         user='demouser',
            ...         password='demopass') as s:
            ...    sh = s.shell('/bin/sh')
            ...    sh.sendline('echo Hello; exit')
            ...    print 'Hello' in sh.recvall()
            True
        """
        return self.run(shell, tty, timeout = timeout)

    def run(self, process, tty = False, wd = None, env = None, timeout = Timeout.default):
        r"""run(process, tty = False, wd = None, env = None, timeout = Timeout.default) -> ssh_channel

        Open a new channel with a specific process inside. If `tty` is True,
        then a TTY is requested on the remote server.

        Return a :class:`pwnlib.tubes.ssh.ssh_channel` object.

        Examples:
            >>> with ssh(host='localhost',
            ...         user='demouser',
            ...         password='demopass') as s:
            ...     py = s.run('python -i')
            ...     _ = py.recvuntil('>>> ')
            ...     py.sendline('print 2+2')
            ...     py.sendline('exit')
            ...     print repr(py.recvline())
            '4\n'
        """

        if wd is None:
            wd = self._wd

        return ssh_channel(self, process, tty, wd, env, timeout)

    def run_to_end(self, process, tty = False, wd = None, env = None):
        r"""run_to_end(process, tty = False, timeout = Timeout.default, env = None) -> str

        Run a command on the remote server and return a tuple with
        (data, exit_status). If `tty` is True, then the command is run inside
        a TTY on the remote server.

        Examples:
            >>> with ssh(host='localhost',
            ...         user='demouser',
            ...         password='demopass') as s:
            ...     print s.run_to_end('echo Hello; exit 17')
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
            >>> with ssh(host='localhost',
            ...         user='demouser',
            ...         password='demopass') as s:
            ...     a = s.connect_remote('localhost', l.lport)
            ...     b = l.wait_for_connection()
            ...     a.sendline('Hello')
            ...     print repr(b.recvline())
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
            >>> with ssh(host='localhost',
            ...         user='demouser',
            ...         password='demopass') as s:
            ...     l = s.listen_remote()
            ...     a = remote('localhost', l.port)
            ...     b = l.wait_for_connection()
            ...     a.sendline('Hello')
            ...     print repr(b.recvline())
            'Hello\n'
        """

        return ssh_listener(self, bind_address, port, timeout)

    def __getitem__(self, attr):
        """Permits indexed access to run commands over SSH

        Examples:

            >>> with ssh(host='localhost',
            ...         user='demouser',
            ...         password='demopass') as s:
            ...     print s['echo hello']
            hello
        """
        return self.__getattr__(attr)()

    def __call__(self, attr):
        """Permits function-style access to run commands over SSH

        Examples:

            >>> with ssh(host='localhost',
            ...         user='demouser',
            ...         password='demopass') as s:
            ...     print repr(s('echo hello'))
            'hello'
        """
        return self.__getattr__(attr)()

    def __getattr__(self, attr):
        """Permits member access to run commands over SSH

        Examples:

            >>> with ssh(host='localhost',
            ...         user='demouser',
            ...         password='demopass') as s:
            ...     print s.echo('hello')
            ...     print s.whoami()
            ...     print s.echo(['huh','yay','args'])
            hello
            demouser
            huh yay args
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

            >>> with ssh(host='localhost',
            ...         user='demouser',
            ...         password='demopass') as s:
            ...     print s.connected()
            ...     s.close()
            ...     print s.connected()
            True
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
            log.failure('Unable to find libraries for %r' % remote)
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
            log.failure('Invalid fingerprint %r' % fingerprint)
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
        total, _ = self.run_to_end('wc -c ' + misc.sh_string(remote))
        total = misc.size(int(total.split()[0]))


        with log.waitfor('Downloading %r' % remote) as h:

            def update(has):
                h.status("%s/%s" % (misc.size(has), total))

            with context.local(log_level = 'ERROR'):
                c = self.run('cat ' + misc.sh_string(remote))
            data = ''

            while True:
                try:
                    data += c.recv()
                except EOFError:
                    break
                update(len(data))

            result = c.wait()
            if result != 0:
                h.failure('Could not download file %r (%r)' % (remote, result))
            else:
                with open(local, 'w') as fd:
                    fd.write(data)
                h.success()

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

        if self._verify_local_fingerprint(fingerprint):
            log.success('Found %r in ssh cache' % remote)
        else:
            self._download_raw(remote, local)

            if not self._verify_local_fingerprint(fingerprint):
                log.error('Could not download file %r' % remote)

        return local

    def download_data(self, remote):
        """Downloads a file from the remote server and returns it as a string.

        Args:
          remote(str): The remote filename to download.


        Examples:
            >>> with file('/tmp/bar','w+') as f:
            ...     f.write('Hello, world')
            >>> with ssh(host='localhost',
            ...         user='demouser',
            ...         password='demopass') as s:
            ...         print s.download_data('/tmp/bar')
            Hello, world
        """

        with open(self._download_to_cache(remote)) as fd:
            return fd.read()

    def download_file(self, remote, local = None):
        """Downloads a file from the remote server.

        The file is cached in /tmp/pwntools-ssh-cache using a hash of the file, so
        calling the function twice has little overhead.

        Args:
          remote(str): The remote filename to download
          local(str): The local filename to save it to. Default is to infer it from the remote filename."""

        if not local:
            local = os.path.basename(os.path.normpath(remote))

        if self._wd and os.path.basename(remote) == remote:
            remote = os.path.join(self._wd, remote)

        local_tmp = self._download_to_cache(remote)
        shutil.copy2(local_tmp, local)

    def download_dir(self, local, remote=None):
        """Recursively uploads a directory onto the remote server

        Args:
            local: Local directory
            remote: Remote directory
        """
        remote   = remote or '.'

        local_wd = os.path.dirname(local) or self._wd
        local    = os.path.basename(local)

        log.info("Downloading %r to %r" % (local,remote))

        source = self.run(['sh', '-c', 'tar -C %s -czf- %s' % (local_wd, local)])
        sink   = process(['sh', '-c', 'tar -C %s -xzf-' % remote])

        source >> sink

        sink.wait_for_close()

    def upload_data(self, data, remote):
        """Uploads some data into a file on the remote server.

        Args:
          data(str): The data to upload.
          remote(str): The filename to upload it to.

        Examoles:
            >>> with ssh(host='localhost',
            ...         user='demouser',
            ...         password='demopass') as s:
            ...     s.upload_data('Hello, world', '/tmp/foo')
            ...     print file('/tmp/foo').read()
            Hello, world
        """

        with context.local(log_level = 'ERROR'):
            s = self.run('cat>' + misc.sh_string(remote))
            s.send(data)
            s.shutdown('send')
            s.recvall()
            if s.wait() != 0:
                log.error("Could not upload file %r" % remote)

    def upload_file(self, filename, remote = None):
        """Uploads a file to the remote server. Returns the remote filename.

        Args:
        filename(str): The local filename to download
        remote(str): The remote filename to save it to. Default is to infer it from the local filename."""


        if remote == None:
            remote = os.path.normpath(filename)
            remote = os.path.basename(remote)

            if self._wd:
                remote = os.path.join(self._wd, remote)

        with open(filename) as fd:
            data = fd.read()

        log.info("Uploading %r to %r" % (filename,remote))
        self.upload_data(data, remote)

        return remote

    def upload_dir(self, local, remote=None):
        """Recursively uploads a directory onto the remote server

        Args:
            local: Local directory
            remote: Remote directory
        """
        remote   = remote or self._wd

        local_wd = os.path.dirname(local)
        local    = os.path.basename(local)

        log.info("Uploading %r to %r" % (local,remote))

        source  = process(['sh', '-c', 'tar -C %s -czf- %s' % (local_wd, local)])
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

        if self._wd:
            s.sendline('cd ' + misc.sh_string(self._wd))

        s.interactive()
        s.close()

    def set_working_directory(self, wd = None):
        """Sets the working directory in which future commands will
        be run (via ssh.run) and to which files will be uploaded/downloaded
        from if no path is provided

        Args:
            wd(string): Working directory.  Default is to auto-generate a directory
                based on the result of running 'mktemp -d' on the remote machine.

        Examples:
            >>> with ssh(host='localhost',
            ...         user='demouser',
            ...         password='demopass') as s:
            ...     cwd = s.set_working_directory()
            ...     print '' == s.ls()
            ...     print s.pwd() == cwd
            True
            True
        """
        status = 0

        if not wd:
            wd, status = self.run_to_end('mktemp -d', wd = None)
            wd = wd.strip()

        if status:
            log.failure("Could not generate a temporary directory")
            return

        _, status = self.run_to_end('ls ' + misc.sh_string(wd), wd = None)

        if status:
            log.failure("%r does not appear to exist" % wd)
            return

        log.info("Working directory: %r" % wd)
        self._wd = wd
        return self._wd
