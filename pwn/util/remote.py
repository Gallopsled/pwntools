import pwn, socket, basesock
from log import *
from consts import *

_DEFAULT_REMOTE_TIMEOUT = 10

class remote(basesock.basesock):
    def __init__(self, host, port = 1337, fam = None, typ = socket.SOCK_STREAM, proto = 0, **kwargs):
        self.target = (host, port)
        if fam is None:
            if host.find(':') <> -1:
                self.family = socket.AF_INET6
            else:
                self.family = socket.AF_INET
        self.type = typ
        self.proto = proto
        self.sock = None
        self.debug = pwn.DEBUG
        self.timeout = kwargs.get('timeout', _DEFAULT_REMOTE_TIMEOUT)
        self.checked = kwargs.get('checked', True)
        self.connect()

    def connect(self):
        if self.connected():
            warning('Already connected to %s on port %d' % self.target)
            return
        waitfor('Opening connection to %s on port %d' % self.target)
        self.sock = socket.socket(self.family, self.type, self.proto)
        if self.timeout is not None:
            self.sock.settimeout(self.timeout)
        if self.checked:
            try:
                self.sock.connect(self.target)
            except socket.error, e:
                if   e.errno == 111:
                    failed('Refused')
                    exit(PWN_UNAVAILABLE)
                elif e.errno == 101:
                    failed('Unreachable')
                    exit(PWN_UNAVAILABLE)
                else:
                    raise
            except socket.timeout:
                failed('Timed out')
                exit(PWN_UNAVAILABLE)
        else:
            self.sock.connect(self.target)
        succeeded()
