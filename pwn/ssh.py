import pwn, sys, time, os, tty, termios, paramiko, re, tempfile, datetime, shutil
from pwn import log, text
from subprocess import Popen, PIPE
from basechatter import basechatter
from select import select

class WarnPolicy(paramiko.MissingHostKeyPolicy):
    '''Policy for what happens when an unknown ssh-fingerprint is encountered''' 
    def __init__(self):
        self.do_warning = False

    def missing_host_key(self, client, hostname, key):
        self.do_warning = True

class ssh_channel(basechatter):
    def __init__(self, parent, process = None, silent = None):
        self.parent = parent
        self._channel = None
        self.exit_status = None
        if silent == None:
            silent = parent.silent
        basechatter.__init__(self, self.parent.timeout, silent)
        self.connect(process)

    def connect(self, process = None):
        if self.connected():
            log.warning('SSH channel is already connected')
            return

        if not self.silent:
            log.waitfor('Opening new channel: "%s"' % (process or 'shell'))

        width, height = pwn.get_term_size()

        self._channel = self.parent._transport.open_session()
        self._channel.get_pty('vt100', width, height)
        self._channel.settimeout(self.timeout)

        # If you ever need stderr with pwntools, then you are likely doing something wrong... AMIRITE?
        self._channel.set_combine_stderr(True)

        if process:
            self._channel.exec_command(process)
        else:
            self._channel.invoke_shell()

        if not self.silent:
            log.succeeded()

    def connected(self):
        return self._channel != None

    def close(self):
        if self._channel:
            if self._channel.exit_status_ready():
                self.exit_status = self._channel.recv_exit_status()
            self._channel.close()
            self._channel = None

    def _send(self, dat):
        while dat:
            n = self._channel.send(dat)
            dat = dat[n:]

    def _recv(self, numb):
        end_time = time.time() + self.timeout

        while True:
            r = ''
            if not self.connected():
                break
            if self._channel.exit_status_ready() and not self._channel.recv_ready():
                self.close()
                break
            try:
                r = self._channel.recv(numb)
            except IOError as e:
                if e.errno != 11:
                    raise
            except socket.timeout:
                pass

            if r or time.time() > end_time:
                break
            time.sleep(0.0001)
        return r

    def fileno(self):
        return self._channel.fileno()

    def interactive(self, prompt = ''):
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        tty.setraw(fd)

        try:
            while True:
                reads, _, _ = select([sys.stdin.fileno(), self._channel.fileno()], [], [], 0.05)

                while self._channel.recv_ready():
                    dat = self.recv()
                    sys.stdout.write(dat)
                    sys.stdout.flush()

                if self._channel.exit_status_ready():
                    if not self._channel.recv_ready():
                        break
                elif sys.stdin.fileno() in reads:
                    dat = sys.stdin.read(1)

                    # Break if ctrl+] is hit
                    if dat == '\x1d':
                        sys.stdout.write('\r\n')
                        sys.stdout.flush()
                        break

                    self.send(dat)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

class ssh:
    def __init__(self, host, user = "root", password = None, port = 22, silent = False, key = None, keyfile = None, keyfiles = None, timeout = 'default'):
        # Save arguments
        self._user = user
        self._password = password
        self._port = port
        self._key = key
        self.silent = silent
        self._keyfiles = ['id_rsa', 'id_dsa']

        if keyfile:
            self._keyfiles.insert(0, keyfile)

        if keyfiles:
            self._keyfiles = keyfiles + self._keyfiles

        # This is an ugly hack to use the same semantics for the timeout
        # as is done for basechatter
        b = basechatter(timeout)
        self.timeout = b.timeout

        # Parse the host string, which can overwrite the arguments
        self._parse_host(host)

        # Initialize variables
        self._client = None
        self._sftp = None

        # Connect to the ssh server
        self.connect()


    def _parse_host(self, host):
        # Split off the optional authentication
        host_ = host.split('@', 1)
        if len(host_) == 1:
            auth, host_ = None, host_[0]
        else:
            auth, host_ = host_

        # Parse the authentication
        if auth:
            auth_ = auth.split(':', 1)
            if len(auth_) == 1:
                self.user = auth_[0]
            else:
                self.user, self.password = auth_

        # Parse the optional port
        host_ = host_.split(':', 1)

        if len(host_) == 1:
            self.host = host_[0]
        else:
            self.host, port = host_

            if not (port and port.isdigit()):
                pwn.die('Port "%s" is not a number' % port)

            self._port = int(port)

    def connect(self):
        if self.connected():
            log.warning('SSH connection to "%s" already started' % self.host)
            return
        if not self.silent:
            log.waitfor('Starting SSH connection to "%s"' % self.host)

        self._keyfiles = [k for k in self._keyfiles if os.path.isfile(k)]

        self._client = paramiko.SSHClient()
        p = WarnPolicy()
        self._client.set_missing_host_key_policy(p)
        self._client.load_system_host_keys()
        self._client.connect(self.host, self._port, self._user, self._password, self._key, self._keyfiles, self.timeout, compress = True)
        self._transport = self._client.get_transport()

        if not self.silent:
            log.succeeded()

            if p.do_warning:
                log.warning('SSH key could not be validated')


    def shell(self, silent = None):
        return ssh_channel(self, silent = silent)

    def run(self, process, silent = None):
        return ssh_channel(self, process, silent)

    def run_simple(self, process):
        c = self.run(process, silent = True)
        dat = c.recvall()
        return dat, c.exit_status

    def connected(self):
        return self._client != None

    def close(self):
        if self._client:
            self._client.close()
            self._client = None

    def libs(self, remote):
        dat, status = self.run_simple('ldd "$(echo %s|base64 -d)"' % pwn.b64(remote))
        if status != 0:
            log.warning('Unable to find libraries for "%s"' % remote)
            return {}

        expr = re.compile(r'(?:([^ ]+) => )?([^(]+)?(?: \(0x[0-9a-f]+\))?$')
        res = {}

        for line in dat.strip().split('\n'):
            line = line.strip()
            parsed = expr.search(line)
            if not parsed:
                log.warning('Could not parse line: "%s"' % line)
            name, resolved = parsed.groups()
            if name == None:
                name = 'ld'

            res[name] = resolved
            if name.startswith('libc.so.'):
                res['libc'] = resolved
        return res

    def _get_fingerprint(self, remote):
        dat, status = self.run_simple('sha256sum "$(echo %s|base64 -d)"' % pwn.b64(remote))
        if status == 0:
            return dat.split()[0]

        dat, status = self.run_simple('sha1sum "$(echo %s|base64 -d)"' % pwn.b64(remote))
        if status == 0:
            return dat.split()[0]

        dat, status = self.run_simple('md5sum "$(echo %s|base64 -d)"' % pwn.b64(remote))
        if status == 0:
            return dat.split()[0]

        return None

    def _get_cachefile(self, fingerprint):
        return os.path.join(self._cachedir, fingerprint)

    def _verify_local_fingerprint(self, fingerprint):
        if not isinstance(fingerprint, str) or \
           len(fingerprint) not in [32, 40, 64] or \
           re.match('[^a-f0-9]', fingerprint):
            log.warning('Invalid fingerprint "%s"' % fingerprint)
            return False

        local = self._get_cachefile(fingerprint)
        if not os.path.isfile(local):
            return False

        func = {32: pwn.md5filehex, 40: pwn.sha1filehex, 64: pwn.sha256filehex}[len(fingerprint)]

        if func(local) == fingerprint:
            return True
        else:
            os.unlink(local)
            return False

    def _initialize_sftp(self):
        if self._sftp == None:
            self._sftp = self._client.open_sftp()

        self._cachedir = os.path.join(tempfile.gettempdir(), 'pwn-ssh-cache')

        if not os.path.isdir(self._cachedir):
            try:
                os.mkdir(self._cachedir)
            except:
                pwn.die('Could not create ssh cache dir: %s' % self._cachedir)

    def _download_raw(self, remote, local):
        self._initialize_sftp()

        if not self.silent:
            log.waitfor('Downloading %s' % remote)

        def update(has, total):
            if not self.silent:
                log.status("%s/%s" % (pwn.size(has), pwn.size(total)))

        self._sftp.get(remote, local, update)

        if not self.silent:
            log.succeeded()

    def download_to_cache(self, remote):
        self._initialize_sftp()
        fingerprint = self._get_fingerprint(remote)
        if fingerprint == None:
            local = os.path.normpath(remote)
            local = os.path.basename(local)
            local += datetime.strftime('-%Y-%m-d-%H:%M:%S')
            local = os.path.join(self._cachedir, local)

            self.download_raw(remote, local)
            return local

        local = self._get_cachefile(fingerprint)

        if self._verify_local_fingerprint(fingerprint):
            if not self.silent:
                log.success('Found %s in ssh cache' % remote)
        else:
            self._download_raw(remote, local)

            if not self._verify_local_fingerprint(fingerprint):
                pwn.die('Could not download file "%s"' % remote)

        return local

    def download(self, remote, local = None, raw = False):
        local_tmp = self.download_to_cache(remote)

        if raw:
            return pwn.read(local_tmp)

        if not local:
            local = os.path.basename(os.path.normpath(remote))

        shutil.copy2(local_tmp, local)

    def download_libs(self, remote, dir = None, only = None):
        libs = self.libs(remote)

        if dir == None:
            dir = self.host

        dir = os.path.realpath(dir)

        res = {}

        seen = set([])

        for lib, remote in libs.items():
            if not remote:
                continue

            if only != None and lib not in only:
                continue

            local = os.path.realpath(os.path.join(dir, './' + remote))
            if not local.startswith(dir):
                pwn.warning('This seems fishy: %s' % remote)
                continue

            dir2 = os.path.dirname(local)

            if not os.path.exists(dir2):
                try:
                    os.makedirs(dir2)
                except:
                    pwn.die('Could not create dir: %s' % dir2)

            if remote not in seen:
                self.download(remote, local)
                seen.add(remote)
            res[lib] = local

        return res

    def upload(self, remote = None, local = None, raw = None):
        self._initialize_sftp()

        if remote == None:
            remote = os.path.normpath(local)
            remote = os.path.basename(remote)

        if raw == None:
            self._sftp.put(local, remote)
        else:
            f = self._sftp.open(remote, 'wb')
            f.write(raw)
            f.close()
