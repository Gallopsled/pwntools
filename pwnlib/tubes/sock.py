import socket, errno, select, logging
from ssl import wrap_socket, SSLSocket
from .tube import tube
from ..timeout import Timeout

log = logging.getLogger(__name__)

class sock(tube):
    r"""Encapsulates a standard socket-like object with a tube interface.

    Examples:

        >>> import socket
        >>> s = socket.create_connection(('google.com', 80))
        >>> s.send('GET /' + '\r\n'*2)
        9
        >>> tubesock = sock(s)
        >>> tubesock.recvline(4)
        'HTTP/1.0 200 OK\r\n'
    """

    default_family = 'any'
    default_type   = 'tcp'
    default_ssl    = False

    def __init__(self,
                 socket  = None,
                 timeout = Timeout.default,
                 ssl     = default_ssl):

        super(sock, self).__init__(timeout)

        self.closed = {"recv": False, "send": False}

        self.sock              = socket
        self.lhost, self.lport = self.sock.getsockname()[:2]
        self.type              = self.sock.type
        self.proto             = self.sock.proto
        self.family            = self.sock.family

        try:
            self.rhost, self.rport = self.sock.getpeername()[:2]
        except:
            self.rhost = self.rport = None

        if ssl:
            self.sock = wrap_socket(self.sock)

        self.settimeout(timeout)

    @staticmethod
    def get_family(fam):

        if isinstance(fam, (int, long)):
            pass
        elif fam == 'any':
            fam = socket.AF_UNSPEC
        elif fam.lower() in ['ipv4', 'ip4', 'v4', '4']:
            fam = socket.AF_INET
        elif fam.lower() in ['ipv6', 'ip6', 'v6', '6']:
            fam = socket.AF_INET6
        else:
            log.error("remote(): family %r is not supported" % fam)

        return fam

    @staticmethod
    def get_type(typ):

        if isinstance(typ, (int, long)):
            pass
        elif typ == "tcp":
            typ = socket.SOCK_STREAM
        elif typ == "udp":
            typ = socket.SOCK_DGRAM
        else:
            log.error("remote(): type %r is not supported" % typ)

        return typ

    # Overwritten for better usability
    def recvall(self):
        """recvall() -> str

        Receives data until the socket is closed.
        """

        if getattr(self, 'type', None) == socket.SOCK_DGRAM:
            log.error("UDP sockets does not supports recvall")
        else:
            return super(sock, self).recvall()

    _eof_exception_errors = [
        errno.EPIPE,
        errno.ECONNRESET,
        errno.ECONNREFUSED
    ]
    def _is_eof_exception(self, e):
        return e.errno in self._eof_exception_errors or e.message == 'Socket is closed'

    def recv_raw(self, numb):
        if not self.connected("recv"):
            raise EOFError

        while True:
            try:
                data = self.sock.recv(numb)
                break
            except socket.timeout:
                return None
            except IOError as e:
                if e.errno == errno.EAGAIN:
                    return None
                elif self._is_eof_exception(e):
                    self.shutdown("recv")
                    raise EOFError
                elif e.errno == errno.EINTR:
                    continue
                else:
                    raise

        if data == '':
            self.shutdown("recv")
            raise EOFError

        return data

    def send_raw(self, data):
        if not self.connected("send"):
            raise EOFError

        try:
            self.sock.sendall(data)
        except IOError as e:
            if self._is_eof_exception(e):
                self.shutdown("send")
                raise EOFError
            else:
                raise

    def settimeout_raw(self, timeout):
        if getattr(self, 'sock', None):
            self.sock.settimeout(timeout)

    def can_recv_raw(self, timeout):
        if not self.connected_raw('recv'):
            return False

        return select.select([self.sock], [], [], timeout) == ([self.sock], [], [])

    def connected_raw(self, direction):
        # The connection is closed via .close()
        if not getattr(self, 'sock', None):
            return False

        # The connection is closed in that direction via .shutdown()
        if self.closed.get(direction, False):
            return False

        # If the socket is wrapped with SSL, we can't call peek directly on it.
        peek_socket = self.sock

        if isinstance(self.sock, SSLSocket):
            peek_socket = self.sock._sock

        try:
            # Don't block
            with self.local(0):
                # Return value of '' implies the connection is closed
                if peek_socket.recv(1, socket.MSG_PEEK | socket.MSG_DONTWAIT):
                    return True
        except IOError as e:
            # Still connected
            if e.errno == errno.EAGAIN:   return True
            # Connection has closed unexpectedly
            if self._is_eof_exception(e): return False
            # Bad things happened
            raise

        return False

    def close(self):
        if not getattr(self, 'sock', None):
            return

        # Call shutdown without triggering another call to close
        self._shutdown_raw_inner(socket.SHUT_RDWR)
        self.closed = {'send': True, 'recv': True}
        self.sock.close()
        self.sock = None
        self._close_msg()

    def _close_msg(self):
        log.info('Closed connection to %s port %d' % (self.rhost, self.rport))

    def fileno(self):
        if not getattr(self, 'sock', None):
            log.error("A closed socket does not have a file number")

        return self.sock.fileno()

    def _shutdown_raw_inner(self, flag):
        try:
            self.sock.shutdown(flag)
        except IOError as e:
            if e.errno in [errno.ENOTCONN, errno.EBADF]:
                pass
            else:
                raise

    def shutdown_raw(self, direction):
        if not self.connected(direction):
            return

        flag = {'send': socket.SHUT_WR,
                'recv': socket.SHUT_RD}[direction]

        self._shutdown_raw_inner(flag)

        self.closed[direction] = True

        if False not in self.closed.values():
            self.close()
