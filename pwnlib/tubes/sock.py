import errno
import select
import socket

from ..log import getLogger
from .tube import tube

log = getLogger(__name__)

class sock(tube):
    """Methods available exclusively to sockets."""

    def __init__(self, *args, **kwargs):
        super(sock, self).__init__(*args, **kwargs)
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

    def recv_raw(self, numb, *a):
        if self.closed["recv"]:
            raise EOFError

        while True:
            try:
                data = self.sock.recv(numb, *a)
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
        """
        Tests:

            >>> l = listen()
            >>> r = remote('localhost', l.lport)
            >>> r.can_recv_raw(timeout=0)
            False
            >>> l.send('a')
            >>> r.can_recv_raw(timeout=1)
            True
            >>> r.recv()
            'a'
            >>> r.can_recv_raw(timeout=0)
            False
            >>> l.close()
            >>> r.can_recv_raw(timeout=1)
            False
            >>> r.closed['recv']
            True
        """
        if not self.sock or self.closed["recv"]:
            return False

        # select() will tell us data is available at EOF
        can_recv = select.select([self.sock], [], [], timeout) == ([self.sock], [], [])

        if not can_recv:
            return False

        # Ensure there's actually data, not just EOF
        try:
            self.recv_raw(1, socket.MSG_PEEK)
        except EOFError:
            return False

        return True

    def connected_raw(self, direction):
        """
        Tests:

            >>> l = listen()
            >>> r = remote('localhost', l.lport)
            >>> r.connected()
            True
            >>> l.close()
            >>> time.sleep(1) # Avoid race condition
            >>> r.connected()
            False
        """
        # If there's no socket, it's definitely closed
        if not self.sock:
            return False

        # If we have noticed a connection close in a given direction before,
        # return fast.
        if self.closed.get(direction, False):
            return False

        # If a connection is closed in all manners, return fast
        if all(self.closed.values()):
            return False

        # Use poll() to determine the connection state
        want = {
            'recv': select.POLLIN,
            'send': select.POLLOUT,
            'any':  select.POLLIN | select.POLLOUT,
        }[direction]

        poll = select.poll()
        poll.register(self, want | select.POLLHUP | select.POLLERR)

        for fd, event in poll.poll(0):
            if event & select.POLLHUP:
                self.close()
                return False
            if event & select.POLLIN:
                return True
            if event & select.POLLOUT:
                return True

        return True

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
