from __future__ import absolute_import
from __future__ import division

import inspect
import logging
import os
import re
import shutil
import six
import string
import sys
import tarfile
import tempfile
import threading
import time
import types

from pwnlib import term
from pwnlib.context import context, LocalContext
from pwnlib.log import Logger
from pwnlib.log import getLogger
from pwnlib.term import text
from pwnlib.timeout import Timeout
from pwnlib.tubes.sock import sock
from pwnlib.util import hashes
from pwnlib.util import misc
from pwnlib.util import safeeval
from pwnlib.util.sh_string import sh_string

# Kill the warning line:
# No handlers could be found for logger "paramiko.transport"
paramiko_log = logging.getLogger("paramiko.transport")
h = logging.StreamHandler(open(os.devnull,'w+'))
h.setFormatter(logging.Formatter())
paramiko_log.addHandler(h)

class ssh_channel(sock):

    #: Parent :class:`ssh` object
    parent = None

    #: Remote host
    host = None

    #: Return code, or :const:`None` if the process has not returned
    #: Use :meth:`poll` to check.
    returncode = None

    #: :const:`True` if a tty was allocated for this channel
    tty = False

    #: Environment specified for the remote process, or :const:`None`
    #: if the default environment was used
    env = None

    #: Command specified for the constructor
    process = None

    def __init__(self, parent, process = None, tty = False, wd = None, env = None, raw = True, *args, **kwargs):
        super(ssh_channel, self).__init__(*args, **kwargs)

        # keep the parent from being garbage collected in some cases
        self.parent = parent

        self.returncode = None
        self.host = parent.host
        self.tty  = tty
        self.env  = env
        self.process = process
        self.cwd  = wd or '.'
        if isinstance(wd, six.text_type):
            wd = context._encode(wd)

        env = env or {}
        msg = 'Opening new channel: %r' % (process or 'shell')

        if isinstance(process, (list, tuple)):
            process = b' '.join(context._encode(sh_string(s)) for s in process)
        if isinstance(process, six.text_type):
            process = context._encode(process)

        if process and wd:
            process = b'cd ' + sh_string(wd) + b' >/dev/null 2>&1; ' + process

        if process and env:
            for name, value in env.items():
                nameb = context._encode(name)
                if not re.match(b'^[a-zA-Z_][a-zA-Z0-9_]*$', nameb):
                    self.error('run(): Invalid environment key %r' % name)
                export = b'export %s=%s;' % (nameb, sh_string(context._encode(value)))
                process = export + process

        if process and tty:
            if raw:
                process = b'stty raw -ctlecho -echo; ' + process
            else:
                process = b'stty -ctlecho -echo; ' + process


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
        tmp_close = self.close
        self.close = lambda: None

        timeout = self.maximum if self.timeout is self.forever else self.timeout
        data = super(ssh_channel, self).recvall(timeout)

        # Restore self.sock to be able to call wait()
        self.close = tmp_close
        self.sock = tmp_sock
        self.wait()
        self.close()

        # Again set self.sock to None
        self.sock = None

        return data

    def wait(self, timeout=sock.default):
        # TODO: deal with timeouts
        return self.poll(block=True)

    def poll(self, block=False):
        """poll() -> int

        Poll the exit code of the process. Will return None, if the
        process has not yet finished and the exit code otherwise.
        """

        if self.returncode is None and self.sock \
        and (block or self.sock.exit_status_ready()):
            while not self.sock.status_event.is_set():
                self.sock.status_event.wait(0.05)
            self.returncode = self.sock.recv_exit_status()

        return self.returncode

    def can_recv_raw(self, timeout):
        with self.countdown(timeout):
            while self.countdown_active():
                if self.sock.recv_ready():
                    return True
                time.sleep(min(self.timeout, 0.05))
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
                    cur = cur.replace(b'\r\n',b'\n')
                    cur = cur.replace(b'\r',b'')
                    if cur is None:
                        continue
                    elif cur == b'\a':
                        # Ugly hack until term unstands bell characters
                        continue
                    stdout = sys.stdout
                    if not term.term_mode:
                        stdout = getattr(stdout, 'buffer', stdout)
                    stdout.write(cur)
                    stdout.flush()
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
                stdin = getattr(sys.stdin, 'buffer', sys.stdin)
                data = stdin.read(1)
                if not data:
                    event.set()
                else:
                    data = bytearray(data)

            if data:
                try:
                    self.send(bytes(bytearray(data)))
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

class ssh_process(ssh_channel):
    #: Working directory
    cwd = None

    #: PID of the process
    #: Only valid when instantiated through :meth:`ssh.process`
    pid = None

    #: Executable of the procesks
    #: Only valid when instantiated through :meth:`ssh.process`
    executable = None

    #: Arguments passed to the process
    #: Only valid when instantiated through :meth:`ssh.process`
    argv = None

    def libs(self):
        """libs() -> dict

        Returns a dictionary mapping the address of each loaded library in the
        process's address space.

        If ``/proc/$PID/maps`` cannot be opened, the output of ldd is used
        verbatim, which may be different than the actual addresses if ASLR
        is enabled.
        """
        maps = self.parent.libs(self.executable)

        maps_raw = self.parent.cat('/proc/%d/maps' % self.pid).decode()

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

        Examples:
            >>> s =  ssh(host='example.pwnme')
            >>> p = s.process('true')
            >>> p.libc  # doctest: +ELLIPSIS
            ELF(.../libc.so.6')
        """
        from pwnlib.elf import ELF

        for lib, address in self.libs().items():
            if 'libc.so' in lib:
                e = ELF(lib)
                e.address = address
                return e

    @property
    def elf(self):
        """elf() -> pwnlib.elf.elf.ELF

        Returns an ELF file for the executable that launched the process.
        """
        import pwnlib.elf.elf

        libs = self.parent.libs(self.executable)

        for lib in libs:
            # Cannot just check "executable in lib", see issue #1047
            if lib.endswith(self.executable):
                return pwnlib.elf.elf.ELF(lib)


    @property
    def corefile(self):
        import pwnlib.elf.corefile

        finder = pwnlib.elf.corefile.CorefileFinder(self)
        if not finder.core_path:
            self.error("Could not find core file for pid %i" % self.pid)

        return pwnlib.elf.corefile.Corefile(finder.core_path)

    def getenv(self, variable, **kwargs):
        r"""Retrieve the address of an environment variable in the remote process.

        Examples:
            >>> s = ssh(host='example.pwnme')
            >>> p = s.process(['python', '-c', 'import time; time.sleep(10)'])
            >>> hex(p.getenv('PATH'))  # doctest: +ELLIPSIS
            '0x...'
        """
        argv0 = self.argv[0]

        variable = context._encode(variable)

        script = ';'.join(('from ctypes import *',
                           'import os',
                           'libc = CDLL("libc.so.6")',
                           'getenv = libc.getenv',
                           'getenv.restype = c_void_p',
                           'print(os.path.realpath(%r))' % self.executable,
                           'print(getenv(%r))' % variable,))

        try:
            with context.quiet:
                python = self.parent.which('python2.7') or self.parent.which('python')

                if not python:
                    self.error("Python is not installed on the remote system.")

                io = self.parent.process([argv0,'-c', script.strip()],
                                          executable=python,
                                          env=self.env,
                                          **kwargs)
                path = io.recvline()
                address = int(io.recvall())

                address -= len(python)
                address += len(path)

                return int(address) & context.mask
        except Exception:
            self.exception("Could not look up environment variable %r" % variable)

    def _close_msg(self):
        # If we never completely started up, just use the parent implementation
        if self.executable is None:
            return super(ssh_process, self)._close_msg()

        self.info('Stopped remote process %r on %s (pid %i)' \
            % (os.path.basename(self.executable),
               self.host,
               self.pid))


class ssh_connecter(sock):
    def __init__(self, parent, host, port, *a, **kw):
        super(ssh_connecter, self).__init__(*a, **kw)

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

            try:
                # Iterate all layers of proxying to get to base-level Socket object
                curr = self.sock.get_transport().sock
                while getattr(curr, "get_transport", None):
                    curr = curr.get_transport().sock

                sockname = curr.getsockname()
                self.lhost = sockname[0]
                self.lport = sockname[1]
            except Exception as e:
                self.exception("Could not find base-level Socket object.")
                raise e

            h.success()

    def spawn_process(self, *args, **kwargs):
        self.error("Cannot use spawn_process on an SSH channel.""")

    def _close_msg(self):
        self.info("Closed remote connection to %s:%d via SSH connection to %s" % (self.rhost, self.rport, self.host))


class ssh_listener(sock):
    def __init__(self, parent, bind_address, port, *a, **kw):
        super(ssh_listener, self).__init__(*a, **kw)

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

    #: Enable caching of SSH downloads (``bool``)
    cache = True

    #: Paramiko SSHClient which backs this object
    client = None

    #: Paramiko SFTPClient object which is used for file transfers.
    #: Set to :const:`None` to disable ``sftp``.
    sftp = None

    #: PID of the remote ``sshd`` process servicing this connection.
    pid = None

    _cwd = '.'

    def __init__(self, user=None, host=None, port=22, password=None, key=None,
                 keyfile=None, proxy_command=None, proxy_sock=None,
                 level=None, cache=True, ssh_agent=False, *a, **kw):
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
            ssh_agent: If :const:`True`, enable usage of keys via ssh-agent

        NOTE: The proxy_command and proxy_sock arguments is only available if a
        fairly new version of paramiko is used.

        Example proxying:

        .. doctest::
           :skipif: True

            >>> s1 = ssh(host='example.pwnme')
            >>> r1 = s1.remote('localhost', 22)
            >>> s2 = ssh(host='example.pwnme', proxy_sock=r1.sock)
            >>> r2 = s2.remote('localhost', 22) # and so on...
            >>> for x in r2, s2, r1, s1: x.close()
        """
        super(ssh, self).__init__(*a, **kw)

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
        self.cache           = cache

        # Deferred attributes
        self._platform_info = {}
        self._aslr = None
        self._aslr_ulimit = None

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
                ssh_config.parse(open(config_file))
                host_config = ssh_config.lookup(host)
                if 'hostname' in host_config:
                    self.host = host = host_config['hostname']
                if not user and 'user' in host_config:
                    self.user = user = host_config['user']
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

            has_proxy = bool(proxy_sock or proxy_command)
            if has_proxy:
                if 'ProxyCommand' not in dir(paramiko):
                    self.error('This version of paramiko does not support proxies.')

                if proxy_sock and proxy_command:
                    self.error('Cannot have both a proxy command and a proxy sock')

                if proxy_command:
                    proxy_sock = paramiko.ProxyCommand(proxy_command)
            else:
                proxy_sock = None

            try:
                self.client.connect(host, port, user, password, key, keyfiles, self.timeout, compress = True, sock = proxy_sock)
            except paramiko.BadHostKeyException as e:
                self.error("Remote host %(host)s is using a different key than stated in known_hosts\n"
                           "    To remove the existing entry from your known_hosts and trust the new key, run the following commands:\n"
                           "        $ ssh-keygen -R %(host)s\n"
                           "        $ ssh-keygen -R [%(host)s]:%(port)s" % locals())

            self.transport = self.client.get_transport()
            self.transport.use_compression(True)

            h.success()

        self._tried_sftp = False

        if self.sftp:
            with context.quiet:
                self.cwd = context._decode(self.pwd())
        else:
            self.cwd = '.'

        with context.local(log_level='error'):
            def getppid():
                print(os.getppid())
            try:
                self.pid = int(self.process('false', preexec_fn=getppid).recvall())
            except Exception:
                self.pid = None

        try:
            self.info_once(self.checksec())
        except Exception:
            self.warn_once("Couldn't check security settings on %r" % self.host)

    def __repr__(self):
        return "{}(user={!r}, host={!r})".format(self.__class__.__name__, self.user, self.host)

    @property
    def cwd(self):
        return self._cwd

    @cwd.setter
    def cwd(self, cwd):
        self._cwd = cwd
        if self.sftp:
            self.sftp.chdir(cwd)

    @property
    def sftp(self):
        if not self._tried_sftp:
            try:
                self._sftp = self.transport.open_sftp_client()
            except Exception:
                self._sftp = None

        self._tried_sftp = True
        return self._sftp

    @sftp.setter
    def sftp(self, value):
        self._sftp = value
        self._tried_sftp = True

    def __enter__(self, *a):
        return self

    def __exit__(self, *a, **kw):
        self.close()

    def shell(self, shell = None, tty = True, timeout = Timeout.default):
        """shell(shell = None, tty = True, timeout = Timeout.default) -> ssh_channel

        Open a new channel with a shell inside.

        Arguments:
            shell(str): Path to the shell program to run.
                If :const:`None`, uses the default shell for the logged in user.
            tty(bool): If :const:`True`, then a TTY is requested on the remote server.

        Returns:
            Return a :class:`pwnlib.tubes.ssh.ssh_channel` object.

        Examples:
            >>> s =  ssh(host='example.pwnme')
            >>> sh = s.shell('/bin/sh')
            >>> sh.sendline(b'echo Hello; exit')
            >>> print(b'Hello' in sh.recvall())
            True
        """
        return self.run(shell, tty, timeout = timeout)

    def process(self, argv=None, executable=None, tty=True, cwd=None, env=None, timeout=Timeout.default, run=True,
                stdin=0, stdout=1, stderr=2, preexec_fn=None, preexec_args=(), raw=True, aslr=None, setuid=None,
                shell=False):
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
                If :const:`None`, ``argv[0]`` is used.
            tty(bool):
                Request a `tty` from the server.  This usually fixes buffering problems
                by causing `libc` to write data immediately rather than buffering it.
                However, this disables interpretation of control codes (e.g. Ctrl+C)
                and breaks `.shutdown`.
            cwd(str):
                Working directory.  If :const:`None`, uses the working directory specified
                on :attr:`cwd` or set via :meth:`set_working_directory`.
            env(dict):
                Environment variables to set in the child.  If :const:`None`, inherits the
                default environment.
            timeout(int):
                Timeout to set on the `tube` created to interact with the process.
            run(bool):
                Set to :const:`True` to run the program (default).
                If :const:`False`, returns the path to an executable Python script on the
                remote server which, when executed, will do it.
            stdin(int, str):
                If an integer, replace stdin with the numbered file descriptor.
                If a string, a open a file with the specified path and replace
                stdin with its file descriptor.  May also be one of ``sys.stdin``,
                ``sys.stdout``, ``sys.stderr``.  If :const:`None`, the file descriptor is closed.
            stdout(int, str):
                See ``stdin``.
            stderr(int, str):
                See ``stdin``.
            preexec_fn(callable):
                Function which is executed on the remote side before execve().
                This **MUST** be a self-contained function -- it must perform
                all of its own imports, and cannot refer to variables outside
                its scope.
            preexec_args(object):
                Argument passed to ``preexec_fn``.
                This **MUST** only consist of native Python objects.
            raw(bool):
                If :const:`True`, disable TTY control code interpretation.
            aslr(bool):
                See :class:`pwnlib.tubes.process.process` for more information.
            setuid(bool):
                See :class:`pwnlib.tubes.process.process` for more information.
            shell(bool):
                Pass the command-line arguments to the shell.

        Returns:
            A new SSH channel, or a path to a script if ``run=False``.

        Notes:
            Requires Python on the remote server.

        Examples:
            >>> s = ssh(host='example.pwnme')
            >>> sh = s.process('/bin/sh', env={'PS1':''})
            >>> sh.sendline(b'echo Hello; exit')
            >>> sh.recvall()
            b'Hello\n'
            >>> s.process(['/bin/echo', b'\xff']).recvall()
            b'\xff\n'
            >>> s.process(['readlink', '/proc/self/exe']).recvall() # doctest: +ELLIPSIS
            b'.../bin/readlink\n'
            >>> s.process(['LOLOLOL', '/proc/self/exe'], executable='readlink').recvall() # doctest: +ELLIPSIS
            b'.../bin/readlink\n'
            >>> s.process(['LOLOLOL\x00', '/proc/self/cmdline'], executable='cat').recvall()
            b'LOLOLOL\x00/proc/self/cmdline\x00'
            >>> sh = s.process(executable='/bin/sh')
            >>> str(sh.pid).encode() in s.pidof('sh') # doctest: +SKIP
            True
            >>> s.process(['pwd'], cwd='/tmp').recvall()
            b'/tmp\n'
            >>> p = s.process(['python','-c','import os; os.write(1, os.read(2, 1024))'], stderr=0)
            >>> p.send(b'hello')
            >>> p.recv()
            b'hello'
            >>> s.process(['/bin/echo', 'hello']).recvall()
            b'hello\n'
            >>> s.process(['/bin/echo', 'hello'], stdout='/dev/null').recvall()
            b''
            >>> s.process(['/usr/bin/env'], env={}).recvall()
            b''
            >>> s.process('/usr/bin/env', env={'A':'B'}).recvall()
            b'A=B\n'

            >>> s.process('false', preexec_fn=1234)
            Traceback (most recent call last):
            ...
            PwnlibException: preexec_fn must be a function

            >>> s.process('false', preexec_fn=lambda: 1234)
            Traceback (most recent call last):
            ...
            PwnlibException: preexec_fn cannot be a lambda

            >>> def uses_globals():
            ...     foo = bar
            >>> print(s.process('false', preexec_fn=uses_globals).recvall().strip().decode()) # doctest: +ELLIPSIS
            Traceback (most recent call last):
            ...
            NameError: ... name 'bar' is not defined

            >>> s.process('echo hello', shell=True).recvall()
            b'hello\n'

            >>> io = s.process(['cat'], timeout=5)
            >>> io.recvline()
            b''
        """
        if not argv and not executable:
            self.error("Must specify argv or executable")

        argv      = argv or []
        aslr      = aslr if aslr is not None else context.aslr

        if isinstance(argv, (six.text_type, bytes, bytearray)):
            argv = [argv]

        if not isinstance(argv, (list, tuple)):
            self.error('argv must be a list or tuple')

        if not all(isinstance(arg, (six.text_type, bytes, bytearray)) for arg in argv):
            self.error("argv must be strings or bytes: %r" % argv)

        if shell:
            if len(argv) != 1:
                self.error('Cannot provide more than 1 argument if shell=True')
            argv = ['/bin/sh', '-c'] + argv

        # Create a duplicate so we can modify it
        argv = list(argv or [])

        # Python doesn't like when an arg in argv contains '\x00'
        # -> execve() arg 2 must contain only strings
        for i, oarg in enumerate(argv):
            if isinstance(oarg, six.text_type):
                arg = oarg.encode('utf-8')
            else:
                arg = oarg
            if b'\x00' in arg[:-1]:
                self.error('Inappropriate nulls in argv[%i]: %r' % (i, oarg))
            argv[i] = bytearray(arg.rstrip(b'\x00'))

        if env is not None and not isinstance(env, dict) and env != os.environ:
            self.error("env must be a dict: %r" % env)

        # Converts the environment variables to a list of tuples to retain order.
        env2 = []
        # Python also doesn't like when envp contains '\x00'
        if env and hasattr(env, 'items'):
            for k, v in env.items():
                if isinstance(k, six.text_type):
                    k = k.encode('utf-8')
                if isinstance(v, six.text_type):
                    v = v.encode('utf-8')
                if b'\x00' in k[:-1]:
                    self.error('Inappropriate nulls in environment key %r' % k)
                if b'\x00' in v[:-1]:
                    self.error('Inappropriate nulls in environment value %r=%r' % (k, v))
                env2.append((bytearray(k.rstrip(b'\x00')), bytearray(v.rstrip(b'\x00'))))
        env = env2 or env

        executable = executable or argv[0]
        cwd        = cwd or self.cwd

        # Validate, since failures on the remote side will suck.
        if not isinstance(executable, (six.text_type, six.binary_type, bytearray)):
            self.error("executable / argv[0] must be a string: %r" % executable)
        executable = context._decode(executable)

        # Allow passing in sys.stdin/stdout/stderr objects
        handles = {sys.stdin: 0, sys.stdout:1, sys.stderr:2}
        stdin  = handles.get(stdin, stdin)
        stdout = handles.get(stdout, stdout)
        stderr = handles.get(stderr, stderr)

        # Allow the user to provide a self-contained function to run
        def func(): pass
        func      = preexec_fn or func
        func_args = preexec_args

        if not isinstance(func, types.FunctionType):
            self.error("preexec_fn must be a function")

        func_name = func.__name__
        if func_name == (lambda: 0).__name__:
            self.error("preexec_fn cannot be a lambda")

        func_src  = inspect.getsource(func).strip()
        setuid = True if setuid is None else bool(setuid)
        
        script = r"""
#!/usr/bin/env python
import os, sys, ctypes, resource, platform, stat
from collections import OrderedDict
try:
    integer_types = int, long
except NameError:
    integer_types = int,
exe   = %(executable)r
argv  = [bytes(a) for a in %(argv)r]
env   = %(env)r

os.chdir(%(cwd)r)

if env is not None:
    env = OrderedDict((bytes(k), bytes(v)) for k,v in env)
    os.environ.clear()
    getattr(os, 'environb', os.environ).update(env)
else:
    env = os.environ

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

if not %(setuid)r:
    PR_SET_NO_NEW_PRIVS = 38
    result = ctypes.CDLL('libc.so.6').prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)

    if result != 0:
        sys.stdout.write('3\n')
        sys.stdout.write("Could not disable setuid: prctl(PR_SET_NO_NEW_PRIVS) failed")
        sys.exit(-1)

try:
    PR_SET_PTRACER = 0x59616d61
    PR_SET_PTRACER_ANY = -1
    ctypes.CDLL('libc.so.6').prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0)
except Exception:
    pass

# Determine what UID the process will execute as
# This is used for locating apport core dumps
suid = os.getuid()
sgid = os.getgid()
st = os.stat(exe)
if %(setuid)r:
    if (st.st_mode & stat.S_ISUID):
        suid = st.st_uid
    if (st.st_mode & stat.S_ISGID):
        sgid = st.st_gid

if sys.argv[-1] == 'check':
    sys.stdout.write("1\n")
    sys.stdout.write(str(os.getpid()) + "\n")
    sys.stdout.write(str(os.getuid()) + "\n")
    sys.stdout.write(str(os.getgid()) + "\n")
    sys.stdout.write(str(suid) + "\n")
    sys.stdout.write(str(sgid) + "\n")
    sys.stdout.write(os.path.realpath(exe) + '\x00')
    sys.stdout.flush()

for fd, newfd in {0: %(stdin)r, 1: %(stdout)r, 2:%(stderr)r}.items():
    if newfd is None:
        os.close(fd)
    elif isinstance(newfd, (str, bytes)):
        newfd = os.open(newfd, os.O_RDONLY if fd == 0 else (os.O_RDWR|os.O_CREAT))
        os.dup2(newfd, fd)
        os.close(newfd)
    elif isinstance(newfd, integer_types) and newfd != fd:
        os.dup2(fd, newfd)

if not %(aslr)r:
    if platform.system().lower() == 'linux' and %(setuid)r is not True:
        ADDR_NO_RANDOMIZE = 0x0040000
        ctypes.CDLL('libc.so.6').personality(ADDR_NO_RANDOMIZE)

    resource.setrlimit(resource.RLIMIT_STACK, (-1, -1))

# Attempt to dump ALL core file regions
try:
    with open('/proc/self/coredump_filter', 'w') as core_filter:
        core_filter.write('0x3f\n')
except Exception:
    pass

# Assume that the user would prefer to have core dumps.
try:
    resource.setrlimit(resource.RLIMIT_CORE, (-1, -1))
except Exception:
    pass

%(func_src)s
%(func_name)s(*%(func_args)r)

os.execve(exe, argv, env)
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

        if self.isEnabledFor(logging.DEBUG):
            execve_repr = "execve(%r, %s, %s)" % (executable,
                                                  argv,
                                                  'os.environ'
                                                  if (env in (None, os.environ))
                                                  else env)
            # Avoid spamming the screen
            if self.isEnabledFor(logging.DEBUG) and len(execve_repr) > 512:
                execve_repr = execve_repr[:512] + '...'
        else:
            execve_repr = repr(executable)

        msg = 'Starting remote process %s on %s' % (execve_repr, self.host)

        if timeout == Timeout.default:
            timeout = self.timeout

        with self.progress(msg) as h:

            script = 'for py in python2.7 python2 python; do test -x "$(which $py 2>&1)" && exec $py -c %s check; done; echo 2' % sh_string(script)
            with context.quiet:
                python = ssh_process(self, script, tty=True, raw=True, level=self.level, timeout=timeout)

            try:
                result = safeeval.const(python.recvline())
            except (EOFError, ValueError):
                h.failure("Process creation failed")
                self.warn_once('Could not find a Python interpreter on %s\n' % self.host \
                               + "Use ssh.run() instead of ssh.process()")
                return None

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
            python.uid  = safeeval.const(python.recvline())
            python.gid  = safeeval.const(python.recvline())
            python.suid = safeeval.const(python.recvline())
            python.sgid = safeeval.const(python.recvline())
            python.argv = argv
            python.executable = context._decode(python.recvuntil(b'\x00')[:-1])

            h.success('pid %i' % python.pid)

        if not aslr and setuid and (python.uid != python.suid or python.gid != python.sgid):
            effect = "partial" if self.aslr_ulimit else "no"
            message = "Specfied aslr=False on setuid binary %s\n" % python.executable
            message += "This will have %s effect.  Add setuid=False to disable ASLR for debugging.\n" % effect

            if self.aslr_ulimit:
                message += "Unlimited stack size should de-randomize shared libraries."

            self.warn_once(message)

        elif not aslr:
            self.warn_once("ASLR is disabled for %r!" % python.executable)

        return python

    def which(self, program):
        """which(program) -> str

        Minor modification to just directly invoking ``which`` on the remote
        system which adds the current working directory to the end of ``$PATH``.
        """
        # If name is a path, do not attempt to resolve it.
        if os.path.sep in program:
            return program

        result = self.run('export PATH=$PATH:$PWD; which %s' % program).recvall().strip().decode()

        if ('/%s' % program) not in result:
            return None

        return result

    def system(self, process, tty = True, wd = None, env = None, timeout = None, raw = True):
        r"""system(process, tty = True, wd = None, env = None, timeout = Timeout.default, raw = True) -> ssh_channel

        Open a new channel with a specific process inside. If `tty` is True,
        then a TTY is requested on the remote server.

        If `raw` is True, terminal control codes are ignored and input is not
        echoed back.

        Return a :class:`pwnlib.tubes.ssh.ssh_channel` object.

        Examples:
            >>> s =  ssh(host='example.pwnme')
            >>> py = s.run('python -i')
            >>> _ = py.recvuntil(b'>>> ')
            >>> py.sendline(b'print(2+2)')
            >>> py.sendline(b'exit')
            >>> print(repr(py.recvline()))
            b'4\n'
            >>> s.system('env | grep -a AAAA', env={'AAAA': b'\x90'}).recvall()
            b'AAAA=\x90\n'
        """

        if wd is None:
            wd = self.cwd

        if timeout is None:
            timeout = self.timeout

        return ssh_channel(self, process, tty, wd, env, timeout = timeout, level = self.level, raw = raw)

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
        except ValueError:
            self.exception("Could not look up environment variable %r" % variable)



    def run_to_end(self, process, tty = False, wd = None, env = None):
        r"""run_to_end(process, tty = False, timeout = Timeout.default, env = None) -> str

        Run a command on the remote server and return a tuple with
        (data, exit_status). If `tty` is True, then the command is run inside
        a TTY on the remote server.

        Examples:
            >>> s =  ssh(host='example.pwnme')
            >>> print(s.run_to_end('echo Hello; exit 17'))
            (b'Hello\n', 17)
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
            >>> s =  ssh(host='example.pwnme')
            >>> a = s.connect_remote(s.host, l.lport)
            >>> a=a; b = l.wait_for_connection()  # a=a; prevents hangs
            >>> a.sendline(b'Hello')
            >>> print(repr(b.recvline()))
            b'Hello\n'
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
            >>> s =  ssh(host='example.pwnme')
            >>> l = s.listen_remote()
            >>> a = remote(s.host, l.port)
            >>> a=a; b = l.wait_for_connection()  # a=a; prevents hangs
            >>> a.sendline(b'Hello')
            >>> print(repr(b.recvline()))
            b'Hello\n'
        """

        return ssh_listener(self, bind_address, port, timeout, level=self.level)

    listen = listen_remote

    def __getitem__(self, attr):
        """Permits indexed access to run commands over SSH

        Examples:

            >>> s =  ssh(host='example.pwnme')
            >>> print(repr(s['echo hello']))
            b'hello'
        """
        return self.__getattr__(attr)()

    def __call__(self, attr):
        """Permits function-style access to run commands over SSH

        Examples:

            >>> s =  ssh(host='example.pwnme')
            >>> print(repr(s('echo hello')))
            b'hello'
        """
        return self.__getattr__(attr)()

    def __getattr__(self, attr):
        """Permits member access to run commands over SSH

        Examples:

            >>> s =  ssh(host='example.pwnme')
            >>> s.echo('hello')
            b'hello'
            >>> s.whoami()
            b'travis'
            >>> s.echo(['huh','yay','args'])
            b'huh yay args'
        """
        bad_attrs = [
            'trait_names',          # ipython tab-complete
        ]

        if attr in self.__dict__ \
        or attr in bad_attrs \
        or attr.startswith('_'):
            raise AttributeError

        @LocalContext
        def runner(*args):
            if len(args) == 1 and isinstance(args[0], (list, tuple)):
                command = [attr] + args[0]
            else:
                command = ' '.join((attr,) + tuple(map(six.ensure_str, args)))

            return self.run(command).recvall().strip()
        return runner

    def connected(self):
        """Returns True if we are connected.

        Example:

            >>> s =  ssh(host='example.pwnme')
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
        escaped_remote = sh_string(remote)
        cmd = ''.join([
            '(',
            'ulimit -s unlimited;',
            'ldd %s > /dev/null &&' % escaped_remote,
            '(',
            'LD_TRACE_LOADED_OBJECTS=1 %s||' % escaped_remote,
            'ldd %s' % escaped_remote,
            '))',
            ' 2>/dev/null'
        ])
        data, status = self.run_to_end(cmd)
        if status != 0:
            self.error('Unable to find libraries for %r' % remote)
            return {}

        return misc.parse_ldd_output(context._decode(data))

    def _get_fingerprint(self, remote):
        cmd = '(sha256 || sha256sum || openssl sha256) 2>/dev/null < '
        cmd = cmd + sh_string(remote)

        data, status = self.run_to_end(cmd)

        if status != 0:
            return None

        # OpenSSL outputs in the format of...
        # (stdin)= e3b0c4429...
        data = data.replace(b'(stdin)= ',b'')

        # sha256 and sha256sum outputs in the format of...
        # e3b0c442...  -
        data = data.replace(b'-',b'').strip()

        if not isinstance(data, str):
            data = data.decode('ascii')

        return data

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
            try:
                self.sftp.get(remote, local, update)
                return
            except IOError:
                pass

        cmd = 'wc -c < ' + sh_string(remote)
        total, exitcode = self.run_to_end(cmd)

        if exitcode != 0:
            h.failure("%r does not exist or is not accessible" % remote)
            return

        total = int(total)

        with context.local(log_level = 'ERROR'):
            cmd = 'cat < ' + sh_string(remote)
            c = self.run(cmd)
        data = b''

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

        with open(local, 'wb') as fd:
            fd.write(data)

    def _download_to_cache(self, remote, p):

        with context.local(log_level='error'):
            remote = self.readlink('-f',remote)
        if not hasattr(remote, 'encode'):
            remote = remote.decode('utf-8')

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
                p.error('Could not download file %r' % remote)

        return local

    def download_data(self, remote):
        """Downloads a file from the remote server and returns it as a string.

        Arguments:
            remote(str): The remote filename to download.


        Examples:
            >>> with open('/tmp/bar','w+') as f:
            ...     _ = f.write('Hello, world')
            >>> s =  ssh(host='example.pwnme',
            ...         cache=False)
            >>> s.download_data('/tmp/bar')
            b'Hello, world'
            >>> s._sftp = None
            >>> s._tried_sftp = True
            >>> s.download_data('/tmp/bar')
            b'Hello, world'

        """
        with self.progress('Downloading %r' % remote) as p:
            with open(self._download_to_cache(remote, p), 'rb') as fd:
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
                remote = self.system('readlink -f ' + sh_string(remote))

        basename = os.path.basename(remote)


        local    = local or '.'
        local    = os.path.expanduser(local)

        self.info("Downloading %r to %r" % (basename,local))

        with context.local(log_level='error'):
            remote_tar = self.mktemp()
            cmd = 'tar -C %s -czf %s %s' % \
                  (sh_string(remote),
                   sh_string(remote_tar),
                   sh_string(basename))
            tar = self.system(cmd)

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
            >>> s =  ssh(host='example.pwnme')
            >>> s.upload_data(b'Hello, world', '/tmp/upload_foo')
            >>> print(open('/tmp/upload_foo').read())
            Hello, world
            >>> s._sftp = False
            >>> s._tried_sftp = True
            >>> s.upload_data(b'Hello, world', '/tmp/upload_bar')
            >>> print(open('/tmp/upload_bar').read())
            Hello, world
        """
        data = context._encode(data)
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
            cmd = 'cat > ' + sh_string(remote)
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


        if remote is None:
            remote = os.path.normpath(filename)
            remote = os.path.basename(remote)
            remote = os.path.join(self.cwd, remote)

        with open(filename, 'rb') as fd:
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
        with self.waitfor(msg):
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
        """upload(file_or_directory, remote=None)

        Upload a file or directory to the remote host.

        Arguments:
            file_or_directory(str): Path to the file or directory to download.
            remote(str): Local path to store the data.
                By default, uses the working directory.
        """
        if isinstance(file_or_directory, str):
            file_or_directory = os.path.expanduser(file_or_directory)
            file_or_directory = os.path.expandvars(file_or_directory)

        if os.path.isfile(file_or_directory):
            return self.upload_file(file_or_directory, remote)

        if os.path.isdir(file_or_directory):
            return self.upload_dir(file_or_directory, remote)

        self.error('%r does not exist' % file_or_directory)

    def download(self, file_or_directory, local=None):
        """download(file_or_directory, local=None)

        Download a file or directory from the remote host.

        Arguments:
            file_or_directory(str): Path to the file or directory to download.
            local(str): Local path to store the data.
                By default, uses the current directory.
        """
        if not self.sftp:
            self.error("Cannot determine remote file type without SFTP")

        with self.system('test -d ' + sh_string(file_or_directory)) as io:
            is_dir = io.wait()

        if 0 == is_dir:
            self.download_dir(file_or_directory, local)
        else:
            self.download_file(file_or_directory, local)

    put = upload
    get = download

    def unlink(self, file):
        """unlink(file)

        Delete the file on the remote host

        Arguments:
            file(str): Path to the file
        """
        if not self.sftp:
            self.error("unlink() is only supported if SFTP is supported")

        return self.sftp.unlink(file)

    def libs(self, remote, directory = None):
        """Downloads the libraries referred to by a file.

        This is done by running ldd on the remote server, parsing the output
        and downloading the relevant files.

        The directory argument specified where to download the files. This defaults
        to './$HOSTNAME' where $HOSTNAME is the hostname of the remote server."""

        libs = self._libs_remote(remote)

        remote = context._decode(self.readlink('-f',remote).strip())
        libs[remote] = 0

        if directory is None:
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
            cmd = 'cd ' + sh_string(self.cwd)
            s.sendline(cmd)

        s.interactive()
        s.close()

    def set_working_directory(self, wd = None, symlink = False):
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
            symlink(bool,str): Create symlinks in the new directory.

                The default value, ``False``, implies that no symlinks should be
                created.

                A string value is treated as a path that should be symlinked.
                It is passed directly to the shell on the remote end for expansion,
                so wildcards work.

                Any other value is treated as a boolean, where ``True`` indicates
                that all files in the "old" working directory should be symlinked.

        Examples:
            >>> s =  ssh(host='example.pwnme')
            >>> cwd = s.set_working_directory()
            >>> s.ls()
            b''
            >>> context._decode(s.pwd()) == cwd
            True

            >>> s =  ssh(host='example.pwnme')
            >>> homedir = s.pwd()
            >>> _=s.touch('foo')

            >>> _=s.set_working_directory()
            >>> assert s.ls() == b''

            >>> _=s.set_working_directory(homedir)
            >>> assert b'foo' in s.ls().split()

            >>> _=s.set_working_directory(symlink=True)
            >>> assert b'foo' in s.ls().split()
            >>> assert homedir != s.pwd()

            >>> symlink=os.path.join(homedir,b'*')
            >>> _=s.set_working_directory(symlink=symlink)
            >>> assert b'foo' in s.ls().split()
            >>> assert homedir != s.pwd()
        """
        status = 0

        if symlink and not isinstance(symlink, (six.binary_type, six.text_type)):
            symlink = os.path.join(self.pwd(), b'*')
        if not hasattr(symlink, 'encode') and hasattr(symlink, 'decode'):
            symlink = symlink.decode('utf-8')

        if not wd:
            wd, status = self.run_to_end('x=$(mktemp -d) && cd $x && chmod +x . && echo $PWD', wd='.')
            wd = wd.strip()

            if status:
                self.error("Could not generate a temporary directory (%i)\n%s" % (status, wd))

        else:
            cmd = b'ls ' + sh_string(wd)
            _, status = self.run_to_end(cmd, wd = '.')

            if status:
                self.error("%r does not appear to exist" % wd)

        if not isinstance(wd, str):
            wd = wd.decode('utf-8')
        self.cwd = wd

        self.info("Working directory: %r" % self.cwd)

        if symlink:
            self.ln('-s', symlink, '.')

        return wd

    def write(self, path, data):
        """Wrapper around upload_data to match :func:`pwnlib.util.misc.write`"""
        return self.upload_data(data, path)

    def read(self, path):
        """Wrapper around download_data to match :func:`pwnlib.util.misc.read`"""
        return self.download_data(path)

    def _init_remote_platform_info(self):
        r"""Fills _platform_info, e.g.:

        ::

            {'distro': 'Ubuntu\n',
             'distro_ver': '14.04\n',
             'machine': 'x86_64',
             'node': 'pwnable.kr',
             'processor': 'x86_64',
             'release': '3.11.0-12-generic',
             'system': 'linux',
             'version': '#19-ubuntu smp wed oct 9 16:20:46 utc 2013'}
        """
        if self._platform_info:
            return

        def preexec():
            import platform
            print('\n'.join(platform.uname()))

        with context.quiet:
            with self.process('true', preexec_fn=preexec) as io:

                self._platform_info = {
                    'system': io.recvline().lower().strip().decode(),
                    'node': io.recvline().lower().strip().decode(),
                    'release': io.recvline().lower().strip().decode(),
                    'version': io.recvline().lower().strip().decode(),
                    'machine': io.recvline().lower().strip().decode(),
                    'processor': io.recvline().lower().strip().decode(),
                    'distro': 'Unknown',
                    'distro_ver': ''
                }

            try:
                if not self.which('lsb_release'):
                    return

                with self.process(['lsb_release', '-irs']) as io:
                    lsb_info = io.recvall().strip().decode()
                    self._platform_info['distro'], self._platform_info['distro_ver'] = lsb_info.split()
            except Exception:
                pass

    @property
    def os(self):
        """:class:`str`: Operating System of the remote machine."""
        try:
            self._init_remote_platform_info()
            with context.local(os=self._platform_info['system']):
                return context.os
        except Exception:
            return "Unknown"


    @property
    def arch(self):
        """:class:`str`: CPU Architecture of the remote machine."""
        try:
            self._init_remote_platform_info()
            with context.local(arch=self._platform_info['machine']):
                return context.arch
        except Exception:
            return "Unknown"

    @property
    def bits(self):
        """:class:`str`: Pointer size of the remote machine."""
        try:
            with context.local():
                context.clear()
                context.arch = self.arch
                return context.bits
        except Exception:
            return context.bits

    @property
    def version(self):
        """:class:`tuple`: Kernel version of the remote machine."""
        try:
            self._init_remote_platform_info()
            vers = self._platform_info['release']

            # 3.11.0-12-generic
            expr = r'([0-9]+\.?)+'

            vers = re.search(expr, vers).group()
            return tuple(map(int, vers.split('.')))

        except Exception:
            return (0,0,0)

    @property
    def distro(self):
        """:class:`tuple`: Linux distribution name and release."""
        try:
            self._init_remote_platform_info()
            return (self._platform_info['distro'], self._platform_info['distro_ver'])
        except Exception:
            return ("Unknown", "Unknown")

    @property
    def aslr(self):
        """:class:`bool`: Whether ASLR is enabled on the system.

        Example:

            >>> s = ssh("travis", "example.pwnme")
            >>> s.aslr
            True
        """
        if self._aslr is None:
            if self.os != 'linux':
                self.warn_once("Only Linux is supported for ASLR checks.")
                self._aslr = False

            else:
                with context.quiet:
                    rvs = self.read('/proc/sys/kernel/randomize_va_space')

                self._aslr = not rvs.startswith(b'0')

        return self._aslr

    @property
    def aslr_ulimit(self):
        """:class:`bool`: Whether the entropy of 32-bit processes can be reduced with ulimit."""
        import pwnlib.elf.elf
        import pwnlib.shellcraft

        if self._aslr_ulimit is not None:
            return self._aslr_ulimit

        # This test must run a 32-bit binary, fix the architecture
        arch = {
            'amd64': 'i386',
            'aarch64': 'arm'
        }.get(self.arch, self.arch)

        with context.local(arch=arch, bits=32, os=self.os, aslr=True):
            with context.quiet:
                try:
                    sc = pwnlib.shellcraft.cat('/proc/self/maps') \
                       + pwnlib.shellcraft.exit(0)

                    elf = pwnlib.elf.elf.ELF.from_assembly(sc, shared=True)
                except Exception:
                    self.warn_once("Can't determine ulimit ASLR status")
                    self._aslr_ulimit = False
                    return self._aslr_ulimit

                def preexec():
                    import resource
                    try:
                        resource.setrlimit(resource.RLIMIT_STACK, (-1, -1))
                    except Exception:
                        pass

                # Move to a new temporary directory
                cwd = self.cwd
                tmp = self.set_working_directory()

                try:
                    self.upload(elf.path, './aslr-test')
                except IOError:
                    self.warn_once("Couldn't check ASLR ulimit trick")
                    self._aslr_ulimit = False
                    return False

                self.process(['chmod', '+x', './aslr-test']).wait()
                maps = self.process(['./aslr-test'], preexec_fn=preexec).recvall()

                # Move back to the old directory
                self.cwd = cwd

                # Clean up the files
                self.process(['rm', '-rf', tmp]).wait()

        # Check for 555555000 (1/3 of the address space for PAE)
        # and for 40000000 (1/3 of the address space with 3BG barrier)
        self._aslr_ulimit = bool(b'55555000' in maps or b'40000000' in maps)

        return self._aslr_ulimit

    def _checksec_cache(self, value=None):
        path = self._get_cachefile('%s-%s' % (self.host, self.port))

        if value is not None:
            with open(path, 'w+') as f:
                f.write(value)
        elif os.path.exists(path):
            with open(path, 'r+') as f:
                return f.read()

    def checksec(self, banner=True):
        """checksec()

        Prints a helpful message about the remote system.

        Arguments:
            banner(bool): Whether to print the path to the ELF binary.
        """
        cached = self._checksec_cache()
        if cached:
            return cached

        red    = text.red
        green  = text.green
        yellow = text.yellow

        res = [
            "%s@%s:" % (self.user, self.host),
            "Distro".ljust(10) + ' '.join(self.distro),
            "OS:".ljust(10) + self.os,
            "Arch:".ljust(10) + self.arch,
            "Version:".ljust(10) + '.'.join(map(str, self.version)),

            "ASLR:".ljust(10) + {
                True: green("Enabled"),
                False: red("Disabled")
            }[self.aslr]
        ]

        if self.aslr_ulimit:
            res += [ "Note:".ljust(10) + red("Susceptible to ASLR ulimit trick (CVE-2016-3672)")]

        cached = '\n'.join(res)
        self._checksec_cache(cached)
        return cached
