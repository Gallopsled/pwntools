from __future__ import absolute_import
from __future__ import division

import errno
import socket

from pwnlib.context import context
from pwnlib.log import getLogger
from pwnlib.timeout import Timeout
from pwnlib.tubes.sock import sock

log = getLogger(__name__)

class listen(sock):
    r"""Creates an TCP or UDP-socket to receive data on. It supports
    both IPv4 and IPv6.

    The returned object supports all the methods from
    :class:`pwnlib.tubes.sock` and :class:`pwnlib.tubes.tube`.

    Arguments:
        port(int): The port to connect to.
            Defaults to a port auto-selected by the operating system.
        bindaddr(str): The address to bind to.
            Defaults to ``0.0.0.0`` / `::`.
        fam: The string "any", "ipv4" or "ipv6" or an integer to pass to :func:`socket.getaddrinfo`.
        typ: The string "tcp" or "udp" or an integer to pass to :func:`socket.getaddrinfo`.

    Examples:

        >>> l = listen(1234)
        >>> r = remote('localhost', l.lport)
        >>> _ = l.wait_for_connection()
        >>> l.sendline(b'Hello')
        >>> r.recvline()
        b'Hello\n'

        >>> # It works with ipv4 by default
        >>> l = listen()
        >>> l.spawn_process('/bin/sh')
        >>> r = remote('127.0.0.1', l.lport)
        >>> r.sendline(b'echo Goodbye')
        >>> r.recvline()
        b'Goodbye\n'

        >>> # and it works with ipv6 by defaut, too!
        >>> l = listen()
        >>> r = remote('::1', l.lport)
        >>> r.sendline(b'Bye-bye')
        >>> l.recvline()
        b'Bye-bye\n'
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

    def __init__(self, port=0, bindaddr='::',
                 fam='any', typ='tcp', *args, **kwargs):
        super(listen, self).__init__(*args, **kwargs)

        port = int(port)

        fam = self._get_family(fam)
        typ = self._get_type(typ)

        if fam == socket.AF_INET and bindaddr == '::':
            bindaddr = '0.0.0.0'

        h = self.waitfor('Trying to bind to %s on port %d' % (bindaddr, port))

        for res in socket.getaddrinfo(bindaddr, port, fam, typ, 0, socket.AI_PASSIVE):
            self.family, self.type, self.proto, self.canonname, self.sockaddr = res

            if self.type not in [socket.SOCK_STREAM, socket.SOCK_DGRAM]:
                continue

            h.status("Trying %s" % self.sockaddr[0])
            listen_sock = socket.socket(self.family, self.type, self.proto)
            listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if self.family == socket.AF_INET6:
                try:
                    listen_sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, fam == socket.AF_INET6)
                except (socket.error, AttributeError):
                    self.warn("could not set socket to accept also IPV4")
            listen_sock.bind(self.sockaddr)
            self.lhost, self.lport = listen_sock.getsockname()[:2]
            if self.type == socket.SOCK_STREAM:
                listen_sock.listen(1)
            break
        else:
            h.failure()
            self.error("Could not bind to %s on port %d" % (bindaddr, port))

        h.success()

        h = self.waitfor('Waiting for connections on %s:%s' % (self.lhost, self.lport))

        def accepter():
            while True:
                try:
                    if self.type == socket.SOCK_STREAM:
                        self.sock, rhost = listen_sock.accept()
                        listen_sock.close()
                    else:
                        data, rhost = listen_sock.recvfrom(4096)
                        listen_sock.connect(rhost)
                        self.sock = listen_sock
                        self.unrecv(data)
                    self.settimeout(self.timeout)
                    break
                except socket.error as e:
                    if e.errno == errno.EINTR:
                        continue
                    h.failure()
                    self.exception("Socket failure while waiting for connection")
                    self.sock = None
                    return

            self.rhost, self.rport = rhost[:2]
            h.success('Got connection from %s on port %d' % (self.rhost, self.rport))

        self._accepter = context.Thread(target = accepter)
        self._accepter.daemon = True
        self._accepter.start()

    def spawn_process(self, *args, **kwargs):
        def accepter():
            self.wait_for_connection()
            self.sock.setblocking(1)
            p = super(listen, self).spawn_process(*args, **kwargs)
            p.wait()
            self.close()
        t = context.Thread(target = accepter)
        t.daemon = True
        t.start()

    def wait_for_connection(self):
        """Blocks until a connection has been established."""
        self.sock
        return self

    def __getattr__(self, key):
        if key == 'sock':
            self._accepter.join(timeout = self.timeout)
            if 'sock' in self.__dict__:
                return self.sock
            else:
                return None
        else:
            return getattr(super(listen, self), key)

    def close(self):
        # since `close` is scheduled to run on exit we must check that we got
        # a connection or the program will hang in the `join` call above
        if self._accepter and self._accepter.is_alive():
            return
        super(listen, self).close()
