from .sock import sock
from .. import log
import socket, sys

class remote(sock):
    """Creates a TCP or UDP-connection to a remote host. It supports
    both IPv4 and IPv6.

    The returned object supports all the methods from
    :class:`pwnlib.pipes.sock` and :class:`pwnlib.pipes.pipe`.

    Args:
      host(str): The host to connect to.
      port(int): The port to connect to.
      fam(str): The string "any", "ipv4" or "ipv6" or an integer to pass to :func:`socket.getaddrinfo`.
      typ(str): The string "tcp" or "udp" or an integer to pass to :func:`socket.getaddrinfo`.
      timeout: A positive number, None or the string "default".
    """

    def __init__(self, host, port,
                 fam = "any", typ = "tcp",
                 timeout = 'default',
                 log_level = log.INFO):
        super(remote, self).__init__(timeout, log_level)

        port = int(port)
        self.target = (host, port)

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

        h = log.waitfor('Opening connection to %s on port %d' % self.target)

        for res in socket.getaddrinfo(host, port, fam, typ, 0, socket.AI_PASSIVE):
            self.family, self.type, self.proto, self.canonname, self.sockaddr = res

            h.status("Trying %s" % self.sockaddr[0])
            self.sock = socket.socket(self.family, self.type, self.proto)
            self.settimeout(self.timeout)
            try:
                self.sock.connect(self.sockaddr)
                self.lhost, self.lport = self.sock.getsockname()[:2]
                break
            except socket.error:
                pass
        else:
            h.failure()
            log.error("Could not connect to %s on port %d" % self.target)
        h.success()
