import pwn, socket, basesock
from pwn import log
from basesock import basesock

class handler(basesock):
    def __init__(self, port = 0, fam = socket.AF_INET, typ = socket.SOCK_STREAM, proto = 0, timeout = 'default'):
        basesock.__init__(self, timeout, silent)
        self.family = fam
        self.type = typ
        self.proto = proto
        self.listensock = None
        self.sock = None
        self.port = port
        self.target = None
        self.start()

    def start(self):
        self.listensock = socket.socket(self.family, self.type, self.proto)
        self.listensock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listensock.settimeout(self.timeout)
        self.listensock.bind(('', self.port))
        self.port = self.listensock.getsockname()[1]
        self.listensock.listen(10)
        if not self.silent:
            log.info('Handler is waiting for connection on {%s}:%d' % (', '.join(i[1] for i in pwn.get_interfaces()), self.port))

    def close(self):
        basesock.close(self)
        if self.listensock:
            self.listensock.close()
            self.listensock = None
            if not self.silent:
                log.info('Stopped handler on port %d' % self.port)

    def wait_for_connection(self):
        if not self.silent:
            log.waitfor('Waiting for connection on port %d' % self.port)

        self.listensock.settimeout(self.timeout)
        try:
            self.sock, self.target = self.listensock.accept()
        except Exception as e:
            if not self.silent:
                log.failed('Got exception: %s' % e)
            raise
        if not self.silent:
            log.succeeded('Got connection from %s:%d' % self.target)
