from .. import log, log_levels, context, term
from ..util import misc
import re, threading, sys

def _fix_timeout(timeout, default):
    if timeout == 'default':
        return default
    elif timeout == None:
        return timeout
    elif isinstance(timeout, (int, long, float)):
        if timeout < 0:
            log.error("timeout cannot be negative")
        else:
            return timeout
    else:
        log.error("timeout must be either a number, None or the string 'default'")

class tube(object):
    """Container of all the tube functions common to both sockets, TTYs and SSH connetions."""

    def __init__(self, timeout, log_level):
        self.buffer          = ''
        self.log_level       = log_level
        self.debug_log_level = min(log_levels.DEBUG, log_level)
        self.timeout         = _fix_timeout(timeout, context.timeout)

    # Functions based on functions from subclasses
    def recv(self, numb = 4096, timeout = 'default'):
        """recv(numb = 4096, timeout = 'default') -> str

        Receives up to `numb` bytes of data from the socket.
        If a timeout occurs while waiting, it will return None.
        If the connection has been closed for receiving,
        :exc:`exceptions.EOFError` will be raised.

        If the string "default" is given as the timeout, then
        the timeout set by the constructor or :func:`settimeout`
        will be used. If None is given, then there will be no timeout.

        It will also print a debug message with log level
        :data:`pwnlib.log_levels.DEBUG` about the received data.
        """

        # If there is already data, go with that
        if self.buffer:
            res = self.buffer[:numb]
            self.buffer = self.buffer[numb:]
            return res

        timeout       = _fix_timeout(timeout, self.timeout)
        old_timeout   = self.timeout
        self.settimeout(timeout)
        data = self.recv_raw(numb)
        self.settimeout(old_timeout)

        if data:
            for line in re.findall('(?:.*\n)|(?:.+$)', data):
                log.debug('Received: %r' % line, log_level = self.debug_log_level)

        return data

    def recvpred(self, pred, timeout = 'default'):
        """recvpred(pred, timeout = 'default') -> str

        Receives one byte at a time from the socket, until ``pred(bytes)``
        evaluates to True.

        If a timeout occurs while waiting, it will return None, and any
        received bytes will be saved for later. It will never return
        partial data, which did not make the predicate become True.

        If the connection has been closed for receiving,
        :exc:`exceptions.EOFError` will be raised.

        .. note::

           Note that any data received before the occurence of an exception,
           will be saved for use by a later receive. This means that
           even if you get an :exc:`exceptions.EOFError`, you might in rare
           cases be able to do a receive anyways.

        If the string "default" is given as the timeout, then
        the timeout set by the constructor or :func:`settimeout`
        will be used. If None is given, then there will be no timeout.
        """

        res = ''

        try:
            while not pred(res):
                cur = self.recv(1, timeout)

                if cur == None:
                    self.buffer = res + self.buffer
                    return None

                res += cur
        except:
            self.buffer = res + self.buffer
            raise

        return res

    def recvn(self, numb, timeout = 'default'):
        """recvn(numb, timeout = 'default') -> str

        Wrapper around :func:`recvpred`, which will return after `numb`
        bytes are available.
        """

        return self.recvpred(lambda buf: len(buf) >= numb, timeout)

    def recvuntil(self, delim, timeout = 'default'):
        """recvuntil(delim, timeout = 'default') -> str

        Wrapper around :func:`recvpred`, which will return when the string
        ends with the given delimiter.
        """

        return self.recvpred(lambda buf: buf.endswith(delim), timeout)

    def recvline(self, lines = 1, timeout = 'default'):
        """recvline(lines = 1, timeout = 'default') -> str

        Wrapper around :func:`recvpred`, which will return then the buffer
        contains ``lines`` number of newlines.
        """

        return self.recvpred(lambda buf: buf.count('\n') == lines, timeout)

    def recvregex(self, regex, exact = False, timeout = 'default'):
        """recvregex(regex, exact = False, timeout = 'default') -> str

        Wrapper around :func:`recvpred`, which will return when a regex
        matches the string in the buffer.

        By default :func:`re.RegexObject.search` is used, but if `exact` is
        set to True, then :func:`re.RegexObject.match` will be used instead.
        """

        if isinstance(regex, (str, unicode)):
            regex = re.compile(regex)

        if exact:
            pred = regex.match
        else:
            pred = regex.search

        return self.recvpred(pred, timeout)

    def recvall(self, breakOnNone=False):
        """recvall() -> str

        Receives data until the socket is closed.

        Args:
            breakOnNone(bool): Return early if a full timeout period passes during which
                no additional data arrives.
        """

        h = log.waitfor('Recieving all data', log_level = self.log_level)

        l = 0
        r = []
        while True:
            try:
                s = self.recv(timeout = None)
            except EOFError:
                break

            if s == None:
                if breakOnNone:
                    break
                else:
                    continue

            r.append(s)
            l += len(s)
            h.status(misc.size(l))

        h.success()

        return ''.join(r)

    def send(self, data):
        """send(data)

        Sends data. Will also print a debug message with
        log level :data:`pwnlib.log_levels.DEBUG` about it.

        If it is not possible to send anymore because of a closed
        connection, it raises and :exc:`exceptions.EOFError`.
        """

        for line in re.findall('(?:.*\n)|(?:.+$)', data):
            log.debug('Send: %r' % line, log_level = self.debug_log_level)
        self.send_raw(data)

    def sendline(self, line):
        """sendline(data)

        Shorthand for ``send(data + '\\n')``.
        """

        self.send(line + '\n')

    def sendafter(self, delim, data, timeout = 'default'):
        """sendafter(delim, data, timeout = 'default') -> str

        A combination of ``recvuntil(delim, timeout)`` and ``send(data)``."""

        res = self.recvuntil(delim, timeout)
        self.send(data)
        return res

    def sendlineafter(self, delim, data, timeout = 'default'):
        """sendlineafter(delim, data, timeout = 'default') -> str

        A combination of ``recvuntil(delim, timeout)`` and ``sendline(data)``."""

        res = self.recvuntil(delim, timeout)
        self.sendline(data)
        return res

    def sendthen(self, delim, data, timeout = 'default'):
        """sendthen(delim, data, timeout = 'default') -> str

        A combination of ``send(data)`` and ``recvuntil(delim, timeout)``."""

        self.send(data)
        return self.recvuntil(delim, timeout)

    def sendlinethen(self, delim, data, timeout = 'default'):
        """sendlinethen(delim, data, timeout = 'default') -> str

        A combination of ``sendline(data)`` and ``recvuntil(delim, timeout)``."""

        self.send(data + '\n')
        return self.recvuntil(delim, timeout)

    def interactive(self, prompt = term.text.bold_red('$') + ' '):
        """interactive(prompt = pwnlib.term.text.bold_red('$') + ' ')

        Does simultaneous reading and writing to the socket. In principle this just
        connects the socket to standard in and standard out, but in practice this
        is much more usable, since we are using :mod:`pwnlib.term` to print a
        floating prompt.

        Thus it only works in while in :data:`pwnlib.term.term_mode`.
        """


        if not term.term_mode:
            log.error("interactive() is not possible outside term_mode")

        log.info('Switching to interactive mode', log_level = self.log_level)

        # Save this to restore later
        debug_log_level = self.debug_log_level
        self.debug_log_level = 0

        go = [True]
        def recv_thread(go):
            while go[0]:
                try:
                    cur = self.recv(timeout = 0.05)
                    if cur == None:
                        continue
                    sys.stdout.write(cur)
                    sys.stdout.flush()
                except EOFError:
                    log.info('Got EOF while reading in interactive', log_level = self.log_level)
                    break

        t = threading.Thread(target = recv_thread, args = (go,))
        t.daemon = True
        t.start()

        try:
            while go[0]:
                data = term.readline.readline(prompt = prompt, float = True)
                if data:
                    try:
                        self.send(data)
                    except EOFError:
                        go[0] = False
                        log.info('Got EOF while sending in interactive',
                                 log_level = self.log_level)
                else:
                    go[0] = False
        except KeyboardInterrupt:
            log.info('Interrupted')

        # Restore
        self.debug_log_level = debug_log_level

    def clean(self, timeout = 0.05):
        """clean()

        Removes all the buffered data from a socket. It does this by calling
        :func:`recv()` until a timeout occurs.

        Args:
            timeout(float): Amount of time which must pass between the arrival of data
                before this routine returns.
        """
        while self.recv(10000, timeout = timeout) != None:
            pass

    def can_recv(self, timeout = 0):
        """can_recv(timeout = 0) -> bool

        Returns True, if there is data available within `timeout` seconds."""

        return bool(self.buffer or self.can_recv_raw(timeout))

    def settimeout(self, timeout):
        """settimeout(timeout)

        Set the timeout for receiving operations. If the string "default"
        is given, then :data:`context.timeout` will be used. If None is given,
        then there will be no timeout.
        """

        self.timeout = _fix_timeout(timeout, context.timeout)
        self.settimeout_raw(self.timeout)

    # The minimal interface to be implemented by a child
    def recv_raw(self, numb):
        """recv_raw(numb) -> str

        Should not be called directly. Receives data without using the buffer
        on the object.

        Unless there is a timeout or closed connection, this should always
        return data. In case of a timeout, it should return None, in case
        of a closed connection it should raise an :exc:`exceptions.EOFError`.
        """

        log.bug('Should be implemented by a subclass.')

    def send_raw(self, data):
        """send_raw(data)

        Should not be called directly. Sends data to the socket.

        Should return :exc:`exceptions.EOFError`, if it is unable to send any
        more, because of a close tube.
        """

        log.bug('Should be implemented by a subclass.')

    def settimeout_raw(self, timeout):
        """settimeout_raw(timeout)

        Should not be called directly. Sets the timeout for
        the socket.
        """

        log.bug('Should be implemented by a subclass.')

    def can_recv_raw(self, timeout):
        """can_recv_raw(timeout) -> bool

        Should not be called directly. Returns True, if
        there is data available within the timeout, but
        ignores the buffer on the object.
        """

        log.bug('Should be implemented by a subclass.')

    def connected(self):
        """connected() -> bool

        Returns True if the socket is connected.
        """

        log.bug('Should be implemented by a subclass.')

    def close(self):
        """close()

        Closes the socket.
        """

        log.bug('Should be implemented by a subclass.')

    def fileno(self):
        """fileno() -> int

        Returns the file number used for reading.
        """

        log.bug('Should be implemented by a subclass.')

    def shutdown(self, direction = "out"):
        """shutdown(direction = "out")

        Calls shutdown on the socket, and thus closing it for either reading or writing.

        Args:
          direction(str): Either the string "in" or "out".
        """

        log.bug('Should be implemented by a subclass.')
