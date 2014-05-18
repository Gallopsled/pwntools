import pwn

from basesock import basesock

class remote(basesock):
    """
        Set up remote TCP connection
    """
    def __init__(self, host, port = 1337,
                 fam = None, typ = None,
                 proto = 0, timeout = 'default',
                 silent = False, logfile = None):
        import socket
        basesock.__init__(self, timeout, silent = silent,logfile = logfile)
        port = int(port)
        self.target = (host, port)
        if fam is None:
            if host.find(':') != -1:
                self.family = socket.AF_INET6
            else:
                self.family = socket.AF_INET
        self.type = typ if typ != None else socket.SOCK_STREAM
        self.proto = proto
        self.sock = None
        self.silent = silent
        self.lhost = None
        self.lport = None
        self.logfile = logfile
        self.connect()

    def connect(self):
        """
            Connect to the host
        """
        import socket
        if self.connected():
            pwn.log.warning('Already connected to %s on port %d' % self.target)
            return
        if not self.silent:
            pwn.log.waitfor('Opening connection to %s on port %d' % self.target)
        self.sock = socket.socket(self.family, self.type, self.proto)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.target)
        self.lhost = self.sock.getsockname()[0]
        self.lport = self.sock.getsockname()[1]

        if self.logfile:
            # Set up logging
            import pwnpcap
            self.logger = pwnpcap.pwnpcap(self.sock.getsockname()[0],self.sock.getpeername()[0],srcport = self.sock.getsockname()[1], dstport = self.sock.getpeername()[1],filename = self.logfile,silent=self.silent)

        if not self.silent:
            pwn.log.succeeded()
