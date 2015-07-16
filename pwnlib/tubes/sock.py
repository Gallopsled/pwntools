import errno
import select
import socket

from ..log import getLogger
from .tube import tube

log = getLogger(__name__)

class sock(tube):
    """Methods available exclusively to sockets."""

    def __init__(self, timeout, level = None):
        super(sock, self).__init__(timeout, level = level)
        self.closed = {"recv": False, "send": False}

    # Overwritten for better usability
    def recvall(self, timeout = tube.forever):
        """recvall() -> str

        Receives data until the socket is closed.
        """

        if getattr(self, 'type', None) == socket.SOCK_DGRAM:
            self.error("UDP sockets does not supports recvall")
        else:
            return super(sock, self).recvall(timeout)

    def recv_raw(self, numb):
        if self.closed["recv"]:
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
                elif e.errno in [errno.ECONNREFUSED, errno.ECONNRESET]:
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
        if self.closed["send"]:
            raise EOFError

        try:
            self.sock.sendall(data)
        except IOError as e:
            eof_numbers = [errno.EPIPE, errno.ECONNRESET, errno.ECONNREFUSED]
            if e.message == 'Socket is closed' or e.errno in eof_numbers:
                self.shutdown("send")
                raise EOFError
            else:
                raise

    def settimeout_raw(self, timeout):
        if getattr(self, 'sock', None):
            self.sock.settimeout(timeout)

    def can_recv_raw(self, timeout):
        if not self.sock or self.closed["recv"]:
            return False

        return select.select([self.sock], [], [], timeout) == ([self.sock], [], [])

    def connected_raw(self, direction):
        if not self.sock:
            return False

        if direction == 'any':
            return True
        elif direction == 'recv':
            return not self.closed['recv']
        elif direction == 'send':
            return not self.closed['send']

    def close(self):
        if not getattr(self, 'sock', None):
            return

        # Mark as closed in both directions
        self.closed['send'] = True
        self.closed['recv'] = True

        self.sock.close()
        self.sock = None
        self._close_msg()

    def _close_msg(self):
        self.info('Closed connection to %s port %d' % (self.rhost, self.rport))

    def fileno(self):
        if not self.sock:
            self.error("A closed socket does not have a file number")

        return self.sock.fileno()

    def shutdown_raw(self, direction):
        if self.closed[direction]:
            return

        self.closed[direction] = True

        if direction == "send":
            try:
                self.sock.shutdown(socket.SHUT_WR)
            except IOError as e:
                if e.errno == errno.ENOTCONN:
                    pass
                else:
                    raise

        if direction == "recv":
            try:
                self.sock.shutdown(socket.SHUT_RD)
            except IOError as e:
                if e.errno == errno.ENOTCONN:
                    pass
                else:
                    raise

        if False not in self.closed.values():
            self.close()
