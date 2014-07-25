import socket, errno, select
from . import tube
from .. import log

class sock(tube.tube):
    """Methods available exclusively to sockets."""

    def __init__(self, timeout, log_level):
        super(sock, self).__init__(timeout, log_level)
        self.closed = {"in": False, "out": False}

    # Functions only available on sock
    def shutdown(self, direction = "out"):
        """shutdown(direction = "out")

        Calls shutdown on the socket, and thus closing it for either reading or writing.

        Args:
          direction(str): Either the string "in" or "out".
        """

        if direction == "out":
            if not self.closed["out"]:
                self.closed["out"] = True
                try:
                    self.sock.shutdown(socket.SHUT_WR)
                except socket.error as e:
                    if e.errno == errno.ENOTCONN:
                        pass
                    else:
                        raise

        if direction == "in":
            if not self.closed["in"]:
                self.closed["in"] = True
                try:
                    self.sock.shutdown(socket.SHUT_RD)
                except socket.error as e:
                    if e.errno == errno.ENOTCONN:
                        pass
                    else:
                        raise

        if False not in self.closed.values():
            self.close()

    # Overwritten for better usability
    def recvall(self):
        """recvall() -> str

        Receives data until the socket is closed.
        """

        if self.type == socket.SOCK_STREAM:
            return super(sock, self).recvall()
        else:
            log.error("UDP sockets does not supports recvall")

    # Implementation of the methods required for tube
    def recv_raw(self, numb):
        if self.closed["in"]:
            raise EOFError

        try:
            data = self.sock.recv(numb)
        except socket.timeout:
            return None
        except socket.error as e:
            if e.errno == errno.EAGAIN:
                return None
            elif e.errno == errno.ECONNREFUSED:
                self.shutdown("in")
                raise EOFError
            elif e.errno == errno.EINTR:
                return ''
            else:
                raise

        if data == '':
            self.shutdown("in")
            raise EOFError
        else:
            return data

    def send_raw(self, data):
        if self.closed["out"]:
            raise EOFError

        try:
            self.sock.sendall(data)
        except socket.error as e:
            if e.errno in [errno.EPIPE, errno.ECONNRESET, errno.ECONNREFUSED]:
                self.shutdown("out")
                raise EOFError
            else:
                raise

    def settimeout_raw(self, timeout):
        if not self.sock:
            return

        if timeout != None and timeout <= 0:
            self.sock.setblocking(0)
        else:
            self.sock.setblocking(1)
            self.sock.settimeout(timeout)

    def can_recv_raw(self, timeout):
        if not self.sock or self.closed["in"]:
            return False

        return select.select([self.sock], [], [], timeout) == ([self.sock], [], [])

    def connected(self):
        return self.sock != None

    def close(self):
        if not self.sock:
            return

        self.sock.close()
        self.sock = None
        self.closed["in"]  = True
        self.closed["out"] = True
        log.info('Closed connection to %s on port %d' % (self.rhost, self.rport), log_level = self.log_level)

    def fileno(self):
        if not self.sock:
            log.error("A closed socket does not have a file number")

        return self.sock.fileno()
