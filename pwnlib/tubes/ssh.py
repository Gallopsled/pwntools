import os, string, base64, paramiko, time, tempfile, threading, sys, shutil, re
from .. import term, log, context
from ..util import hashes, misc
from . import sock, tube


class ssh_channel(sock.sock):
    def __init__(self, parent, process = None, tty = False, wd = None, env = None, timeout = 'default'):
        super(ssh_channel, self).__init__(timeout)

        # keep the parent from being garbage collected in some cases
        self.parent = parent

        self.returncode = None
        self.host = parent.host
        self.tty  = tty

        env = env or {}

        h = log.waitfor('Opening new channel: %r' % ((process,) or 'shell'))

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

    def wait(self):
        return self.poll(block=True)

    def poll(self, block=False):
        """poll() -> int

        Poll the exit code of the process. Will return None, if the
        process has not yet finished and the exit code otherwise.
        """

        if self.returncode == None:
            if block or (self.sock and self.sock.exit_status_ready()):
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

        go = [True]
        def recv_thread(go):
            while go[0]:
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
                    go[0] = False
                    break

        t = threading.Thread(target = recv_thread, args = (go,))
        t.daemon = True
        t.start()

        while go[0]:
            if term.term_mode:
                try:
                    data = term.key.getraw(0.1)
                except KeyboardInterrupt:
                    data = [3] # This is ctrl-c
                except IOError:
                    if go[0]:
                        raise
            else:
                data = sys.stdin.read(1)
                if not data:
                    go[0] = False

            if data:
                try:
                    self.send(''.join(chr(c) for c in data))
                except EOFError:
                    go[0] = False
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

class ssh_connecter(sock.sock):
    def __init__(self, parent, host, port, timeout = 'default'):
        super(ssh_connecter, self).__init__(timeout)

        # keep the parent from being garbage collected in some cases
        self.parent = parent

        self.host  = parent.host
        self.rhost = host
        self.rport = port

        h = log.waitfor('Connecting to %s:%d via SSH to %s' % (self.rhost, self.rport, self.host))
        try:
            self.sock = parent.transport.open_channel('direct-tcpip', (host, port), ('127.0.0.1', 0))
        except:
            h.failure()
            raise

        h.success()

    def spawn_process(self, *args, **kwargs):
        log.error("Cannot use spawn_process on an SSH channel.""")

    def _close_msg(self):
        log.info("Closed remote connection to %s:%d via SSH connection to %s" % (self.rhost, self.rport, self.host))


class ssh_listener(sock.sock):
    def __init__(self, parent, bind_address, port, timeout = 'default'):
        super(ssh_listener, self).__init__(timeout)

        # keep the parent from being garbage collected in some cases
        self.parent = parent

        self.host = parent.host
        self.port = port

        h = log.waitfor('Waiting on port %d via SSH to %s' % (self.port, self.host))
        try:
            parent.transport.request_port_forward(bind_address, self.port)
        except:
            h.failure('Failed create a port forwarding')
            raise

        def accepter():
            try:
                self.sock = parent.transport.accept()
                parent.transport.cancel_port_forward(bind_address, self.port)
            except:
                self.sock = None
                h.failure('Failed to get a connection')
                return

            self.rhost, self.rport = self.sock.origin_addr
            h.success('Got connection from %s:%d' % (self.rhost, self.rport))

        self._accepter = threading.Thread(target = accepter)
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


class ssh(object):
    def __init__(self, user, host, port = 22, password = None, key = None, keyfile = None, proxy_command = None, proxy_sock = None, timeout = 'default'):
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

        self.host            = host
        self.port            = port
        self.timeout         = tube._fix_timeout(timeout, context.timeout)
        self._cachedir       = os.path.join(tempfile.gettempdir(), 'pwntools-ssh-cache')
        self._wd             = None
        misc.mkdir_p(self._cachedir)

        keyfiles = [os.path.expanduser(keyfile)] if keyfile else []

        h = log.waitfor('Connecting to %s on port %d' % (host, port))
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

    def shell(self, tty = True, timeout = 'default'):
        """shell(tty = False, timeout = 'default') -> ssh_channel

        Open a new channel with a shell inside. If `tty` is True, then a TTY
        is requested on the remote server.

        Return a :class:`pwnlib.tubes.ssh.ssh_channel` object.
        """
        return self.run(None, tty, timeout = timeout)

    def run(self, process, tty = False, wd = 'default', env = None, timeout = 'default'):
        """run(process, tty = False, wd = 'default', env = None, timeout = 'default') -> ssh_channel

        Open a new channel with a specific process inside. If `tty` is True,
        then a TTY is requested on the remote server.

        Return a :class:`pwnlib.tubes.ssh.ssh_channel` object."""

        timeout = tube._fix_timeout(timeout, self.timeout)

        if wd == 'default':
            wd = self._wd

        return ssh_channel(self, process, tty, wd, env, timeout)

    def run_to_end(self, process, tty = False, wd = 'default', env = None):
        """run_to_end(process, tty = False, timeout = 'default', env = None) -> str

        Run a command on the remote server and return a tuple with
        (data, exit_status). If `tty` is True, then the command is run inside
        a TTY on the remote server."""

        with context.local(log_level = 'silent'):
            c = self.run(process, tty, wd = wd, timeout = None)
            data = c.recvall()
            retcode = c.wait()
            c.close()
            return data, retcode

    def connect_remote(self, host, port, timeout = 'default'):
        """connect_remote(host, port, timeout = 'default') -> ssh_connecter

        Connects to a host through an SSH connection. This is equivalent to
        using the ``-L`` flag on ``ssh``.

        Returns a :class:`pwnlib.tubes.ssh.ssh_connecter` object."""

        return ssh_connecter(self, host, port, timeout)

    def listen_remote(self, port, bind_address = '', timeout = 'default'):
        """listen_remote(port, bind_address = '', timeout = 'default') -> ssh_connecter

        Listens remotely through an SSH connection. This is equivalent to
        using the ``-R`` flag on ``ssh``.

        Returns a :class:`pwnlib.tubes.ssh.ssh_listener` object."""

        return ssh_listener(self, bind_address, port, timeout)

    def __getitem__(self, attr):
        """Permits indexed access to run commands over SSH

        >>> s = ssh(host='bandit.labs.overthewire.org', # doctest: +SKIP
        ...         user='bandit0',
        ...         password='bandit0')
        >>> s['echo hello'] # doctest: +SKIP
        'hello'
        """
        return self.__getattr__(attr)()

    def __getattr__(self, attr):
        """Permits member access to run commands over SSH

        >>> s = ssh(host='bandit.labs.overthewire.org', # doctest: +SKIP
        ...         user='bandit0',
        ...         password='bandit0')
        >>> s.echo('hello') # doctest: +SKIP
        'hello'
        >>> s.whoami() # doctest: +SKIP
        'bandit0'
        >>> s.echo(['huh','yay','args']) # doctest: +SKIP
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
        """Returns True if we are connected."""
        return self.client != None

    def close(self):
        """Close the connection."""
        if self.client:
            self.client.close()
            self.client = None
            log.info("Closed connection to %r" % self.host)

    def _libs_remote(self, remote):
        """Return a dictionary of the libraries used by a remote file."""
        data, status = self.run_to_end('ulimit -s unlimited; ldd ' + misc.sh_string(remote))
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

        h = log.waitfor('Downloading %r' % remote)

        def update(has):
            h.status("%s/%s" % (misc.size(has), total))

        with context.local(log_level = 'silent'):
            c = self.run('cat ' + misc.sh_string(remote))
        data = ''

        while True:
            try:
                data += c.recv()
            except EOFError:
                break
            update(len(data))

        if c.wait() != 0:
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
          remote(str): The remote filename to download."""

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

    def upload_data(self, data, remote):
        """Uploads some data into a file on the remote server.

        Args:
          data(str): The data to upload.
          remote(str): The filename to upload it to."""

        with context.local(log_level = 'silent'):
            s = self.run('cat>' + misc.sh_string(remote))
            s.send(data)
            s.shutdown('send')
            s.recvall()
            if s.wait() != 0:
                log.error("Could not upload file %r" % remote)

    def upload_file(self, filename, remote = None):
        """Uploads a file to the remote server.

        Args:
        remote(str): The local filename to download
        local(str): The remote filename to save it to. Default is to infer it from the local filename."""


        if remote == None:
            remote = os.path.normpath(filename)
            remote = os.path.basename(remote)

            if self._wd:
                remote = os.path.join(self._wd, remote)

        with open(filename) as fd:
            data = fd.read()

        log.info("Uploading %r to %r" % (filename,remote))
        self.upload_data(data, remote)

        return misc.parse_ldd_output(remote)

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

    def interactive(self):
        """Create an interactive session.

        This is a simple wrapper for creating a new
        :class:`pwnlib.tubes.ssh.ssh_channel` object and calling
        :meth:`pwnlib.tubes.ssh.ssh_channel.interactive` on it."""

        s = self.shell()

        if self._wd:
            s.sendline('cd %r' % self._wd)

        s.interactive()
        s.close()

    def set_working_directory(self, wd = None):
        """Sets the working directory in which future commands will
        be run (via ssh.run) and to which files will be uploaded/downloaded
        from if no path is provided

        Args:
            wd(string): Working directory.  Default is to auto-generate a directory
                based on the result of running 'mktemp -d' on the remote machine.
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
