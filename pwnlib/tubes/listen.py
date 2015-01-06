from .sock     import sock
from ..timeout import Timeout
from ..context import context
import socket, errno, logging

log = logging.getLogger(__name__)

class listen(sock):
    r"""Listens on a socket for exactly one incoming connection.

    Args:
        port(int): The port to connect to.
        bindaddr(str): The address to bind to.
        family: The string "any", "ipv4" or "ipv6" or an integer to pass to :func:`socket.getaddrinfo`.
        type: The string "tcp" or "udp" or an integer to pass to :func:`socket.getaddrinfo`.
        timeout: A positive number, None

    Examples:

        >>> import socket
        >>> l = listen(0)
        >>> s = socket.create_connection(('localhost', l.lport))
        >>> _ = l.wait_for_connection()
        >>> s.send('hello')
        5
        >>> l.recv()
        'hello'

        Only one connection is accepted.

        >>> socket.create_connection(('localhost', l.lport))
        Traceback (most recent call last):
        ...
        error: [Errno 61] Connection refused

        UDP works in a similar fashion, and binds to the first host
        that data is received from.

        >>> l = listen(type='udp')
        >>> s = socket.socket(type=socket.SOCK_DGRAM)
        >>> s.sendto('hello', ('localhost', l.lport))
        5
        >>> l.recv()
        'hello'

        IPv6 also works by default

        >>> l = listen(0, '::')
        >>> s = socket.create_connection(('::1', l.lport))
        >>> _ = l.wait_for_connection()
        >>> s.send('hello')
        5
        >>> l.recv()
        'hello'
        >>> l = listen(0, family='ipv6')
        >>> s = socket.create_connection(('::1', l.lport))
        >>> _ = l.wait_for_connection()
        >>> s.send('hello')
        5
        >>> l.recv()
        'hello'

        You can also replicate the functionality of 'nc -e' to create
        a socket server that automatically launches a binary.

        >>> l = listen()
        >>> l.spawn_process('sh')
        >>> s = socket.create_connection(('localhost', l.lport))
        >>> s.send('echo hello; exit;\n')
        18
        >>> s.recv(1024)
        'hello\n'

    """

    def __init__(self,
                 port     = 0,
                 bindaddr = "0.0.0.0",
                 family   = sock.default_family,
                 type     = sock.default_type,
                 timeout  = Timeout.default,
                 ssl      = sock.default_ssl):

        port   = int(port)
        family = self.get_family(family)
        type   = self.get_type(type)

        msg = 'Trying to bind to %s on port %d' % (bindaddr, port)
        with log.waitfor(msg) as h:

            for res in socket.getaddrinfo(bindaddr, port, family, type, 0, socket.AI_PASSIVE):
                f, t, p, _canonname, sockaddr = res

                if t not in [socket.SOCK_STREAM, socket.SOCK_DGRAM]:
                    continue

                h.status("Trying %s" % sockaddr[0])
                listen_sock = socket.socket(f, t, p)
                listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listen_sock.bind(sockaddr)

                if t == socket.SOCK_STREAM:
                    listen_sock.listen(1)
                break
            else:
                log.error("Could not bind to %s on port %d" % (bindaddr, port))

        # We now have a socket to initialize, pass it to the sock constructor
        super(listen, self).__init__(socket=listen_sock, timeout=timeout, ssl=ssl)

        self._accepter = context.Thread(target = self._accepter_thread)
        self._accepter.daemon = True
        self._accepter.start()

    def _accepter_thread(self):
        msg = 'Waiting for connections on %s:%s' % (self.lhost, self.lport)
        with log.waitfor(msg) as h:
            while True:
                try:
                    if self.type == socket.SOCK_STREAM:
                        client, rhost = self.sock.accept()
                        self.sock.close()

                        self.sock = client
                    else:
                        data, rhost = self.sock.recvfrom(4096)
                        self.sock.connect(rhost)
                        self.unrecv(data)
                    self.settimeout(self.timeout)
                    break
                except socket.error as e:
                    if e.errno == errno.EINTR:
                        continue
                    log.exception("Socket failure while waiting for connection")
                    self.sock = None
                    return

            self.rhost, self.rport = rhost[:2]

            h.success('Got connection from %s on port %d' % (self.rhost, self.rport))


    def spawn_process(self, *args, **kwargs):
        def accepter():
            self.wait_for_connection()
            p = super(listen, self).spawn_process(*args, **kwargs)
            p.wait()
            self.close()

        t = context.Thread(target = accepter)
        t.daemon = True
        t.start()


    def wait_for_connection(self, timeout=Timeout.default):
        """Blocks until a connection has been established.

        Arguments:
            timeout(int): Maximum time to wait for a connection
        """
        with self.countdown(timeout):
            while self.countdown_active() and self._accepter.is_alive():
                self._accepter.join(timeout = 0.1)

        return self

    #: Alias for :meth:`wait_for_connection`
    accept = wait_for_connection

    def close(self):
        # since `close` is scheduled to run on exit we must check that we got
        # a connection or the program will hang in the `join` call above
        if self._accepter.is_alive():
            return
        super(listen, self).close()
