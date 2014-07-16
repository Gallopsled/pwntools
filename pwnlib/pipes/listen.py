from .sock import sock
from .. import log
import socket, sys, time

class listen(sock):
    """Creates an TCP or UDP-socket to receive data on. It supports
    both IPv4 and IPv6.

    The returned object supports all the methods from
    :class:`pwnlib.pipes.sock` and :class:`pwnlib.pipes.pipe`.

    UDP servers are only partially supported, as the methods in those classes
    are not using :meth:`socket.socket.sendto` or :meth:`socket.socket.recvfrom`.

    Args:
      port(int): The port to connect to.
      bindaddr(str): The address to bind to.
      fam(str): The string "any", "ipv4" or "ipv6" or an integer to pass to :func:`socket.getaddrinfo`.
      typ(str): The string "tcp" or "udp" or an integer to pass to :func:`socket.getaddrinfo`.
      timeout: A positive number, None or the string "default".
    """

    def __init__(self, port, bindaddr = "0.0.0.0",
                 fam = "any", typ = "tcp",
                 timeout = 'default',
                 log_level = log.INFO):
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
            log.error("remote(): family %s is not supported" % repr(fam))

        if typ == "tcp":
            typ = socket.SOCK_STREAM
        elif typ == "udp":
            typ = socket.SOCK_DGRAM
        elif isinstance(typ, (int, long)):
            pass
        else:
            log.error("remote(): type %s is not supported" % repr(typ))

        h = log.waitfor('Trying to bind to %s on port %d' % (bindaddr, port))

        for res in socket.getaddrinfo(bindaddr, port, fam, typ, 0, socket.AI_PASSIVE):
            self.family, self.type, self.proto, self.canonname, self.sockaddr = res

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
        if self.type == socket.SOCK_DGRAM:
            self.sock = listen_sock
        else:
            listen_sock.listen(1)

            h = log.waitfor('Waiting for incomming connection')

            try:
                self.sock, _ = listen_sock.accept()
                listen_sock.close()
                self.settimeout(self.timeout)
            except socket.error:
                h.failure()
                log.error("Socket failure while waiting for connection")
            h.success()

        self.lhost, self.lport = self.sock.getsockname()[:2]
