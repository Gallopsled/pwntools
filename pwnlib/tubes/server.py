from __future__ import absolute_import

import errno
import socket

from pwnlib.context import context
from pwnlib.log import getLogger
from pwnlib.tubes.sock import sock
from pwnlib.tubes.remote import remote

log = getLogger(__name__)

class server(sock):
    r"""Creates an TCP or UDP-server to listen for connections. It supports
    both IPv4 and IPv6.

    The callback function should take a :class:`pwnlib.tubes.remote` as
    its only argument.

    Arguments:
        port(int): The port to connect to.
            Defaults to a port auto-selected by the operating system.
        bindaddr(str): The address to bind to.
            Defaults to ``0.0.0.0`` / `::`.
        fam: The string "any", "ipv4" or "ipv6" or an integer to pass to :func:`socket.getaddrinfo`.
        typ: The string "tcp" or "udp" or an integer to pass to :func:`socket.getaddrinfo`.
        callback: The function to run with the new connection.

    Examples:

        >>> s = server(8888)
        >>> r1 = remote('localhost', s.lport)
        >>> r2 = remote('localhost', s.lport)
        >>> r1.sendline("Hello")
        >>> r2.sendline("Hi")
        >>> r2.recvline()
        'Hi\n'
        >>> r1.recvline()
        'Hello\n'
        >>> def callback(conn):
        ...     s = conn.recvline()
        ...     conn.send(s[::-1])
        ...
        >>> t = server(8889, callback=callback)
        >>> r3 = remote('localhost', t.lport)
        >>> r3.sendline('callback')
        >>> r3.recv()
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

    def __init__(self, port=0, bindaddr = "0.0.0.0",
                 fam = "any", typ = "tcp", callback = None, *args, **kwargs):
        super(server, self).__init__(*args, **kwargs)

        port = int(port)
        fam  = {socket.AF_INET: 'ipv4',
                socket.AF_INET6: 'ipv6'}.get(fam, fam)

        fam = self._get_family(fam)
        typ = self._get_type(typ)

        if fam == socket.AF_INET6 and bindaddr == '0.0.0.0':
            bindaddr = '::'

        def echo(remote):
            while True:
                s = remote.readline()
                remote.send(s)

        if not callback:
            callback = echo

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

        def accepter():
            while True:
                h = self.waitfor('Waiting for connections on %s:%s' % (self.lhost, self.lport))
                while True:
                    try:
                        if self.type == socket.SOCK_STREAM:
                            sock, rhost = listen_sock.accept()
                            rhost, rport = rhost[:2]
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

                r = remote(rhost, rport, sock = sock)
                t = context.Thread(target = callback, args = (r,))
                t.daemon = False
                t.start()
                h.success('Got connection from %s on port %d' % (rhost, rport))

        self._accepter = context.Thread(target = accepter)
        self._accepter.daemon = False
        self._accepter.start()

    def close(self):
        self._accepter.close()
        # since `close` is scheduled to run on exit we must check that we got
        # a connection or the program will hang in the `join` call above
        if self._accepter and self._accepter.is_alive():
            return
        super(server, self).close()
