from __future__ import absolute_import
from __future__ import division

import errno
import socket
import threading

from pwnlib.context import context
from pwnlib.log import getLogger
from pwnlib.tubes.sock import sock
from pwnlib.tubes.remote import remote

log = getLogger(__name__)

class server(sock):
    r"""Creates an TCP or UDP-server to listen for connections. It supports
    both IPv4 and IPv6.

    Arguments:
        port(int): The port to connect to.
            Defaults to a port auto-selected by the operating system.
        bindaddr(str): The address to bind to.
            Defaults to ``0.0.0.0`` / `::`.
        fam: The string "any", "ipv4" or "ipv6" or an integer to pass to :func:`socket.getaddrinfo`.
        typ: The string "tcp" or "udp" or an integer to pass to :func:`socket.getaddrinfo`.
        callback: A function to be started on incoming connections. It should take a :class:`pwnlib.tubes.remote` as its only argument.

    Examples:

        >>> s = server(8888)
        >>> client_conn = remote('localhost', s.lport)
        >>> server_conn = s.next_connection()
        >>> client_conn.sendline(b'Hello')
        >>> server_conn.recvline()
        'Hello\n'
        >>> def cb(r):
        ...     client_input = r.readline()
        ...     r.send(client_input[::-1])
        ...
        >>> t = server(8889, callback=cb)
        >>> client_conn = remote('localhost', t.lport)
        >>> client_conn.sendline(b'callback')
        >>> client_conn.recv()
        '\nkcabllac'
    """

    #: Local port
    lport = 0

    #: Local host
    lhost = None

    #: Socket type (e.g. socket.SOCK_STREAM)
    type = None

    #: Socket family
    family = None

    #: Socket protocol
    protocol = None

    #: Canonical name of the listening interface
    canonname = None

    #: Sockaddr structure that is being listened on
    sockaddr = None

    _accepter = None

    def __init__(self, port=0, bindaddr = "0.0.0.0", fam = "any", typ = "tcp",
                 callback = None, blocking = False, *args, **kwargs):
        super(server, self).__init__(*args, **kwargs)

        port = int(port)
        fam  = {socket.AF_INET: 'ipv4',
                socket.AF_INET6: 'ipv6'}.get(fam, fam)

        fam = self._get_family(fam)
        typ = self._get_type(typ)

        if fam == socket.AF_INET6 and bindaddr == '0.0.0.0':
            bindaddr = '::'

        h = self.waitfor('Trying to bind to %s on port %d' % (bindaddr, port))

        for res in socket.getaddrinfo(bindaddr, port, fam, typ, 0, socket.AI_PASSIVE):
            self.family, self.type, self.proto, self.canonname, self.sockaddr = res

            if self.type not in [socket.SOCK_STREAM, socket.SOCK_DGRAM]:
                continue

            h.status("Trying %s" % self.sockaddr[0])
            listen_sock = socket.socket(self.family, self.type, self.proto)
            listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listen_sock.bind(self.sockaddr)
            self.lhost, self.lport = listen_sock.getsockname()[:2]
            if self.type == socket.SOCK_STREAM:
                listen_sock.listen(1)
            break
        else:
            h.failure()
            self.error("Could not bind to %s on port %d" % (bindaddr, port))

        h.success()

        self.sock = listen_sock
        self.connections_waiting = threading.Event()
        self.connections = []
        def accepter():
            while True:
                h = self.waitfor('Waiting for connections on %s:%s' % (self.lhost, self.lport))
                while True:
                    try:
                        if self.type == socket.SOCK_STREAM:
                            sock, rhost = listen_sock.accept()
                        else:
                            data, rhost = listen_sock.recvfrom(4096)
                            listen_sock.connect(rhost)
                            sock = listen_sock
                            sock.unrecv(data)
                        sock.settimeout(self.timeout)
                        break
                    except socket.error as e:
                        if e.errno == errno.EINTR:
                            continue
                        h.failure()
                        self.exception("Socket failure while waiting for connection")
                        sock = None
                        return

                self.rhost, self.rport = rhost[:2]
                r = remote(self.rhost, self.rport, sock = sock)
                h.success('Got connection from %s on port %d' % (self.rhost, self.rport))
                if callback:
                    if not blocking:
                        t = context.Thread(target = callback, args = (r,))
                        t.daemon = True
                        t.start()
                    else:
                        callback(r)
                else:
                    self.connections.append(r)
                    if not self.connections_waiting.is_set():
                        self.connections_waiting.set()

        self._accepter = context.Thread(target = accepter)
        self._accepter.daemon = True
        self._accepter.start()

    def next_connection(self):
        if not self.connections_waiting.is_set():
            self.connections_waiting.wait()
        conn = self.connections.pop(0)
        if not self.connections:
            self.connections_waiting.clear()
        return conn

    def close(self):
        # since `close` is scheduled to run on exit we must check that we got
        # a connection or the program will hang in the `join` call above
        if self._accepter and self._accepter.is_alive():
            return
        super(server, self).close()
