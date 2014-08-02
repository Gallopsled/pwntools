from . import sock
from .. import log, log_levels
import socket, errno

class listen(sock.sock):
    """Creates an TCP or UDP-socket to receive data on. It supports
    both IPv4 and IPv6.

    The returned object supports all the methods from
    :class:`pwnlib.tubes.sock` and :class:`pwnlib.tubes.tube`.

    Args:
      port(int): The port to connect to.
      bindaddr(str): The address to bind to.
      fam: The string "any", "ipv4" or "ipv6" or an integer to pass to :func:`socket.getaddrinfo`.
      typ: The string "tcp" or "udp" or an integer to pass to :func:`socket.getaddrinfo`.
      timeout: A positive number, None or the string "default".
    """

    def __init__(self, port, bindaddr = "0.0.0.0",
                 fam = "any", typ = "tcp",
                 timeout = 'default',
                 log_level = log_levels.INFO):
        super(listen, self).__init__(timeout, log_level)

        port = int(port)

        if fam == 'any':
            fam = socket.AF_UNSPEC
        elif fam == 4 or fam.lower() in ['ipv4', 'ip4', 'v4', '4']:
            fam = socket.AF_INET
        elif fam == 6 or fam.lower() in ['ipv6', 'ip6', 'v6', '6']:
            fam = socket.AF_INET6
        elif isinstance(fam, (int, long)):
            pass
        else:
            log.error("remote(): family %r is not supported" % fam)

        if typ == "tcp":
            typ = socket.SOCK_STREAM
        elif typ == "udp":
            typ = socket.SOCK_DGRAM
        elif isinstance(typ, (int, long)):
            pass
        else:
            log.error("remote(): type %r is not supported" % typ)

        h = log.waitfor('Trying to bind to %s on port %d' % (bindaddr, port), log_level = self.log_level)

        for res in socket.getaddrinfo(bindaddr, port, fam, typ, 0, socket.AI_PASSIVE):
            self.family, self.type, self.proto, self.canonname, self.sockaddr = res

            if self.type not in [socket.SOCK_STREAM, socket.SOCK_DGRAM]:
                continue

            h.status("Trying %s" % self.sockaddr[0])
            listen_sock = socket.socket(self.family, self.type, self.proto)
            listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                listen_sock.bind(self.sockaddr)
                break
            except socket.error:
                pass
        else:
            h.failure()
            log.error("Could not bind to %s on port %d" % (bindaddr, port))

        h.success()

        h = log.waitfor('Waiting', log_level = self.log_level)
        while True:
            try:
                if self.type == socket.SOCK_STREAM:
                    listen_sock.listen(1)
                    self.sock, self.rhost = listen_sock.accept()
                    listen_sock.close()
                else:
                    self.sock = listen_sock
                    self.buffer, self.rhost = self.sock.recvfrom(4096)
                    self.sock.connect(self.rhost)
                self.settimeout(self.timeout)
                break
            except socket.error as e:
                if e.errno == errno.EINTR:
                    continue
                h.failure()
                log.error("Socket failure while waiting for connection")
                break

        self.lhost, self.lport = self.sock.getsockname()[:2]
        self.rhost, self.rport = self.rhost[:2]
        h.success('Got connection from %s on port %d' % (self.rhost, self.rport))
