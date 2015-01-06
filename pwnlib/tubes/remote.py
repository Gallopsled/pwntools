from .sock import sock
from ..timeout import Timeout
import socket, logging
import ssl as _ssl

log = logging.getLogger(__name__)

class remote(sock):
    r"""Creates a connection to a remote host.

    Args:
        host(str): The host to connect to.
        port(int): The port to connect to.
        family: The string "any", "ipv4" or "ipv6" or an integer to pass to :func:`socket.getaddrinfo`.
        type: The string "tcp" or "udp" or an integer to pass to :func:`socket.getaddrinfo`.
        timeout: A positive number, None or the string "default".
        ssl(bool): Wrap the socket with SSL
        sock(socket): Socket to inherit, rather than connecting

    Examples:

        >>> r = remote('google.com', 443, ssl=True)
        >>> r.send('GET /\r\n\r\n')
        >>> r.recvn(4)
        'HTTP'
        >>> r = remote('127.0.0.1', 1)
        Traceback (most recent call last):
        ...
        PwnlibException: Could not connect to 127.0.0.1 on port 1
    """

    def __init__(self, host, port,
                 family  = sock.default_family,
                 type    = sock.default_type,
                 timeout = Timeout.default,
                 ssl     = sock.default_ssl):

        # We need a Timeout object before calling super.__init__,
        # in order to turn 'timeout' into an integer value.
        tmp_timeout = Timeout(timeout)

        msg = 'Opening connection to %s on port %d' % (host, port)

        with log.waitfor(msg) as h:
            family = self.get_family(family)
            type = self.get_type(type)

            for res in socket.getaddrinfo(host, port, family, type, 0, socket.AI_PASSIVE):
                f, t, p, _canonname, sockaddr = res

                if t not in [socket.SOCK_STREAM, socket.SOCK_DGRAM]:
                    continue

                h.status("Trying %s" % sockaddr[0])

                try:
                    sock = socket.socket(f, t, p)
                    sock.settimeout(tmp_timeout.timeout)
                    sock.connect(sockaddr)
                    break
                except socket.error:
                    pass
            else:
                log.error("Could not connect to %s on port %d" % (host, port))
                return

        super(remote, self).__init__(socket=sock, timeout=timeout, ssl=ssl)
