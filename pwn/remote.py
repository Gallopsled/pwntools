import pwn, socket, basesock, errno
from pwn import log
from basesock import basesock

class remote(basesock):
    def __init__(self, host, port = 1337, fam = None, typ = socket.SOCK_STREAM, proto = 0, timeout = 'default'):
        basesock.__init__(self, timeout)
        port = int(port)
        self.target = (host, port)
        if fam is None:
            if host.find(':') != -1:
                self.family = socket.AF_INET6
            else:
                self.family = socket.AF_INET
        self.type = typ
        self.proto = proto
        self.sock = None
        self.lhost = None
        self.lport = None
        self.connect()

    def connect(self):
        if self.connected():
            log.warning('Already connected to %s on port %d' % self.target)
            return
        log.waitfor('Opening connection to %s on port %d' % self.target)
        self.sock = socket.socket(self.family, self.type, self.proto)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.target)
        self.lhost = self.sock.getsockname()[0]
        self.lport = self.sock.getsockname()[1]
        log.succeeded()
