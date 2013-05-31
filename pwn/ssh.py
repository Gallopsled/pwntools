import pwn, sys, time, os, tty, termios
from pwn import log, text
from subprocess import Popen, PIPE
from basechatter import basechatter
import time
import paramiko
from select import select

class WarnPolicy(paramiko.MissingHostKeyPolicy):
    def __init__(self):
        self.do_warning = False

    def missing_host_key(self, client, hostname, key):
        self.do_warning = True

class ssh(basechatter):
    def __init__(self, host, user = "root", password = None, port = 22, key = None, keyfile = None, keyfiles = None, timeout = 'default', silent = False, shell = False, process = None):
        self.silent = silent
        self.user = user
        self.port = port
        self.password = password
        self.key = key
        self.client = None
        self.channel = None
        self.sftp = None
        self.process = process
        basechatter.__init__(self, timeout)

        if keyfile:
            self.keyfiles = [keyfile, 'id_rsa', 'id_dsa']
        else:
            self.keyfiles = ['id_rsa', 'id_dsa']

        if keyfiles:
            self.keyfiles = keyfiles + self.keyfiles

        self.parse_host(host)
        self.connect()

        if shell:
            self.shell()
        elif self.process:
            self.run(self.process)
        del self.process

    def parse_host(self, host):
        host_ = host.split('@', 1)

        if len(host_) == 1:
            auth, host_ = None, host_[0]
        else:
            auth, host_ = host_

        if auth:
            auth_ = auth.split(':', 1)
            if len(auth_) == 1:
                self.user = auth_[0]
            else:
                self.user, self.password = auth_

        host_ = host_.split('#', 1)

        if len(host_) == 1:
            host_ = host_[0]
        else:
            host_, self.process = host_

        host_ = host_.split(':', 1)

        if len(host_) == 1:
            self.host = host_[0]
        else:
            self.host, port = host_
            
            if not (port and port.isdigit()):
                pwn.die('Port "%s" is not a number' % port)

            self.port = int(port)

    def connect(self):
        if self.connected():
            log.warning('SSH connection to "%s" already started' % self.host)
            return
        if not self.silent:
            log.waitfor('Starting SSH connection to "%s"' % self.host)

        self.keyfiles = [k for k in self.keyfiles if os.path.isfile(k)]

        self.client = paramiko.SSHClient()
        p = WarnPolicy()
        self.client.set_missing_host_key_policy(p)
        self.client.load_system_host_keys()
        self.client.connect(self.host, self.port, self.user, self.password, self.key, self.keyfiles, self.timeout, compress = True)
        self.transport = self.client.get_transport()

        if not self.silent:
            log.succeeded()

        if p.do_warning:
            log.warning('SSH key could not be validated')

    def _start(self, process):
        if self.active():
            log.warning('SSH connection to "%s" already have an active channel' % self.host)
            return

        width, height = pwn.get_term_size()

        self.channel = self.transport.open_session()
        self.channel.get_pty('vt100', width, height)
        self.channel.settimeout(self.timeout)

        # If you ever need stderr with pwntools, then you are likely doing something wrong... AMIRITE?
        self.channel.set_combine_stderr(True)

        if process:
            self.channel.exec_command(process)
        else:
            self.channel.invoke_shell()

    def shell(self):
        self._start(None)

    def run(self, process):
        self._start(process)

    def connected(self):
        return self.client != None

    def active(self):
        return self.connected() and self.channel != None

    def close(self):
        if self.client:
            self.client.close()
            self.client = None

    def close_session(self):
        if self.channel:
            self.channel.close()
            self.channel = None

    def _send(self, dat):
        while dat:
            n = self.channel.send(dat)
            dat = dat[n:]

    def _recv(self, numb):
        end_time = time.time() + self.timeout

        while True:
            r = ''
            if not self.active():
                break
            if self.channel.exit_status_ready() and not self.channel.recv_ready():
                self.close_session()
                break
            try:
                r = self.channel.recv(numb)
            except IOError as e:
                if e.errno != 11:
                    raise
            except socket.timeout:
                pass

            if r or time.time() > end_time:
                break
            time.sleep(0.0001)
        return r

    def recvall(self, close = False):
        return basechatter.recvall(self, close)

    def fileno(self):
        return self.channel.fileno()

    def interactive(self, prompt = ''):
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        tty.setraw(fd)

        try:
            while True:
                reads, _, _ = select([sys.stdin.fileno(), self.channel.fileno()], [], [], 0.05)

                while self.channel.recv_ready():
                    dat = self.recv()
                    sys.stdout.write(dat)
                    sys.stdout.flush()

                if self.channel.exit_status_ready():
                    if not self.channel.recv_ready():
                        break
                elif sys.stdin.fileno() in reads:
                    dat = sys.stdin.read(1)

                    # Break if ctrl+] is hit
                    if dat == '\x1d':
                        break

                    self.send(dat)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        print
