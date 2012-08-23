import pwn, socket, basesock
from consts import *

_DEFAULT_HANDLER_TIMEOUT = 10
_DEFAULT_HANDLER_BACKLOG = 10

class handler(basesock.basesock):
    def __init__(self, fam = socket.AF_INET, typ = socket.SOCK_STREAM, proto = 0, **kwargs):
        self.family = fam
        self.type = typ
        self.proto = proto
        self.listensock = None
        self.sock = None
        self.port = None
        self.target = None
        self.debug = pwn.DEBUG
        self.timeout = kwargs.get('timeout', _DEFAULT_HANDLER_TIMEOUT)
        self.backlog = kwargs.get('backlog', _DEFAULT_HANDLER_BACKLOG)
        self.checked = kwargs.get('checked', True)
        self.start()

    def start(self):
        self.listensock = socket.socket(self.family, self.type, self.proto)
        if self.timeout is not None:
            self.listensock.settimeout(self.timeout)
        self.listensock.bind(('localhost', 0))
        self.port = self.listensock.getsockname()[1]
        self.listensock.listen(self.backlog)
        pwn.trace(' [+] Handler is waiting for connection on port %d\n' % self.port)

    def stop(self):
        if self.listensock:
            self.listensock.close()
            self.listensock = None
            pwn.trace(' [+] Stopped handler on port %d\n' % self.port)
            self.port = None

    def wait_for_connection(self):
        if self.checked:
            try:
                self.sock, self.target = self.listensock.accept()
            except socket.timeout:
                pwn.trace(' [-] Handler on port %s timed out\n' % self.port)
                exit(PWN_PATCHED)
        else:
            self.sock, self.target = self.listensock.accept()
        pwn.trace(' [+] Got connection on local port %d from %s:%d\n' % ((self.port,) + self.target))

    def settimeout(self, n):
        self.timeout = n
        self.listensock.settimeout(n)
        self.sock.settimeout(n)
