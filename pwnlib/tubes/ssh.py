import os, string, base64, paramiko, time, tempfile, threading, sys, shutil
from .. import term, log_levels, log, context
from ..util import hashes, misc
from . import sock, tube


class ssh_channel(sock.sock):
    def __init__(self, parent, process = None, tty = False, wd = None, timeout = 'default', log_level = log_levels.INFO):
        super(ssh_channel, self).__init__(timeout, log_level)

        self.returncode = None
        self.host = parent.host
        self.tty  = tty

        h = log.waitfor('Opening new channel: %r' % (process or 'shell'), log_level = self.log_level)

        if isinstance(process, (list, tuple)):
            process = ' '.join(misc.sh_string(s) for s in process)

        if process and wd:
            process = "cd %s 2>/dev/null >/dev/null; %s" % (misc.sh_string(wd), process)

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

    def poll(self):
        """poll() -> int

        Poll the exit code of the process. Will return None, if the
        process has not yet finished and the exit code otherwise.
        """

        if self.returncode == None:
            if self.sock and self.sock.exit_status_ready():
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

        if not term.term_mode:
            log.error("interactive() is not possible outside term_mode")

        log.info('Switching to interactive mode', log_level = self.log_level)

        # Save this to restore later
        debug_log_level = self.debug_log_level
        self.debug_log_level = 0

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
                    log.info('Got EOF while reading in interactive', log_level = self.log_level)
                    go[0] = False
                    break

        t = threading.Thread(target = recv_thread, args = (go,))
        t.daemon = True
        t.start()

        while go[0]:
            try:
                data = term.key.getraw(0.1)
            except KeyboardInterrupt:
                data = [3] # This is ctrl-c
            except IOError:
                if go[0]:
                    raise

            if data:
                try:
                    self.send(''.join(chr(c) for c in data))
                except EOFError:
                    go[0] = False
                    log.info('Got EOF while sending in interactive',
                             log_level = self.log_level)

        while t.is_alive():
            t.join(timeout = 0.1)

        # Restore
        self.debug_log_level = debug_log_level
        term.term.hide_cursor()

    def close(self):
        self.poll()
        while self.resizer in term.term.on_winch:
            term.term.on_winch.remove(self.resizer)
        super(ssh_channel, self).close()

    def _close_msg(self):
        log.info('Closed SSH channel with %s' % self.host, log_level = self.log_level)


class ssh_connecter(sock.sock):
    def __init__(self, parent, host, port, timeout = 'default', log_level = log_levels.INFO):
        super(ssh_connecter, self).__init__(timeout, log_level)

        self.host  = parent.host
        self.rhost = host
        self.rport = port

        h = log.waitfor('Connecting to %s:%d via SSH to %s' % (self.rhost, self.rport, self.host), log_level = self.log_level)
        try:
            self.sock = parent.transport.open_channel('direct-tcpip', (host, port), ('127.0.0.1', 0))
        except:
            h.failed()
            raise

        h.success()

    def _close_msg(self):
        log.info("Closed remote connection to %s:%d via SSH connection to %s" % (self.rhost, self.rport, self.host))


class ssh_listener(sock.sock):
    def __init__(self, parent, bind_address, port, timeout = 'default', log_level = log_levels.INFO):
        super(ssh_listener, self).__init__(timeout, log_level)

        self.host = parent.host
        self.port = port

        h = log.waitfor('Waiting on port %d via SSH to %s' % (self.port, self.host), log_level = self.log_level)
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

    def wait_for_connection(self):
        """Blocks until a connection has been established."""
        self.sock

    def __getattr__(self, key):
        if key == 'sock':
            while self._acceptor.is_alive():
                self._accepter.join(timeout = 0.1)
            return self.sock
        else:
            return getattr(super(ssh_listener, self), key)


class ssh(object):
    def __init__(self, user, host, port = 22, password = None, key = None, keyfile = None, proxy_command = None, proxy_sock = None, timeout = 'default', log_level = log_levels.INFO):
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
        self.log_level       = log_level
        self._cachedir       = os.path.join(tempfile.gettempdir(), 'pwntools-ssh-cache')
        self._wd             = None
        misc.mkdir_p(self._cachedir)

        keyfiles = [keyfile] if keyfile else []

        h = log.waitfor('Connecting to %s on port %d' % (host, port), log_level = self.log_level)
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

    def shell(self, tty = True, timeout = 'default', log_level = 'default'):
        """shell(tty = False, timeout = 'default', log_level = 'default') -> ssh_channel

        Open a new channel with a shell inside. If `tty` is True, then a TTY
        is requested on the remote server.

        Return a :class:`pwnlib.tubes.ssh.ssh_channel` object.
        """
        return self.run(None, tty, None, timeout, log_level)

    def run(self, process, tty = False, wd = 'default', timeout = 'default', log_level = 'default'):
        """run(process, tty = False, timeout = 'default', log_level = 'default', wd = 'default') -> ssh_channel

        Open a new channel with a specific process inside. If `tty` is True,
        then a TTY is requested on the remote server.

        Return a :class:`pwnlib.tubes.ssh.ssh_channel` object."""

        if log_level == 'default':
            log_level = self.log_level

        timeout = tube._fix_timeout(timeout, self.timeout)

        if wd == 'default':
            wd = self._wd

        return ssh_channel(self, process, tty, wd, timeout, log_level)

    def run_to_end(self, process, tty = False, wd = 'default'):
        """run_to_end(process, tty = False, timeout = 'default') -> str

        Run a command on the remote server and return a tuple with
        (data, exit_status). If `tty` is True, then the command is run inside
        a TTY on the remote server."""

        c = self.run(process, tty, wd, None, 0)
        data = c.recvall()
        retcode = c.poll()
        c.close()
        return data, retcode

    def connect_remote(self, host, port, timeout = 'default', log_level = 'default'):
        """connect_remote(host, port, timeout = 'default', log_level = 'default') -> ssh_connecter

        Connects to a host through an SSH connection. This is equivalent to
        using the ``-L`` flag on ``ssh``.

        Returns a :class:`pwnlib.tubes.ssh.ssh_connecter` object."""

        return ssh_connecter(self, host, port, timeout, log_level)

    def listen_remote(self, port, bind_address = '', timeout = 'default', log_level = 'default'):
        """listen_remote(port, bind_address = '', timeout = 'default', log_level = 'default') -> ssh_connecter

        Listens remotely through an SSH connection. This is equivalent to
        using the ``-R`` flag on ``ssh``.

        Returns a :class:`pwnlib.tubes.ssh.ssh_listener` object."""

        return ssh_listener(self, bind_address, port, timeout, log_level)

    def connected(self):
        """Returns True if we are connected."""
        return self.client != None

    def close(self):
        """Close the connection."""
        if self.client:
            self.client.close()
            self.client = None
            log.info("Closed connection to %r" % self.host, log_level = self.log_level)

    def _libs_remote(self, remote):
        """Return a dictionary of the libraries used by a remote file."""
        data, status = self.run_to_end('ldd ' + misc.sh_string(remote))
        if status != 0:
            log.failure('Unable to find libraries for %r' % remote)
            return {}

        return misc.parse_ldd_output(data)

    def _get_fingerprint(self, remote):
        arg = misc.sh_string(remote)
        cmd = '(sha256sum %s||sha1sum %s||md5sum %s) 2>/dev/null' % (arg, arg, arg)
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

        h = log.waitfor('Downloading %r' % remote, log_level = self.log_level)

        def update(has):
            h.status("%s/%s" % (misc.size(has), total))

        c = self.run('cat ' + misc.sh_string(remote), log_level = 0)
        data = ''

        while True:
            try:
                data += c.recv()
            except EOFError:
                break
            update(len(data))

        if c.poll() != 0:
            h.failure('Could not download file %r' % remote)
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
            log.success('Found %r in ssh cache' % remote, log_level = self.log_level)
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

        s = self.run('cat>' + misc.sh_string(remote), log_level = 0)
        s.send(data)
        s.shutdown('out')
        s.recvall()
        if s.poll() != 0:
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

        return remote

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

        for lib, remote in libs.items():
            if not remote or lib == 'linux':
                continue

            local = os.path.realpath(os.path.join(directory, '.' + os.path.sep + remote))
            if not local.startswith(directory):
                log.warning('This seems fishy: %r' % remote)
                continue

            misc.mkdir_p(os.path.dirname(local))

            if remote not in seen:
                self.download_file(remote, local)
                seen.add(remote)
            res[lib] = local

        return res

    def interactive(self):
        """Create an interactive session.

        This is a simple wrapper for creating a new
        :class:`pwnlib.tubes.ssh.ssh_channel` object and calling
        :meth:`pwnlib.tubes.ssh.ssh_channel.interactive` on it."""

        s = self.shell()
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
