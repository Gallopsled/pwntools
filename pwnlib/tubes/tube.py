from .. import log, log_levels, context, term
from ..util import misc
import re, threading, sys, time, subprocess

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

        Receives up to `numb` bytes of data from the tube.
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

        Receives one byte at a time from the tube, until ``pred(bytes)``
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

    def recvrepeat(self, timeout = 'default'):
        """recvrepeat()

        Receives data until a timeout or EOF is reached."""

        timeout = _fix_timeout(timeout, self.timeout)

        if timeout == None:
            timeout = 0.1

        r = []
        while True:
            try:
                s = self.recv(10000, timeout = timeout)
            except EOFError:
                break

            if s == None:
                break

            r.append(s)

        return ''.join(r)

    def recvall(self):
        """recvall() -> str

        Receives data until EOF is reached.
        """

        h = log.waitfor('Recieving all data', log_level = self.log_level)

        l = 0
        r = []
        while True:
            try:
                s = self.recv(timeout = 0.1)
            except EOFError:
                break

            if s == None:
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

        Does simultaneous reading and writing to the tube. In principle this just
        connects the tube to standard in and standard out, but in practice this
        is much more usable, since we are using :mod:`pwnlib.term` to print a
        floating prompt.

        Thus it only works in while in :data:`pwnlib.term.term_mode`.
        """


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
                if term.term_mode:
                    data = term.readline.readline(prompt = prompt, float = True)
                else:
                    data = sys.stdin.read(1)

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

        while t.is_alive():
            t.join(timeout = 0.1)

        # Restore
        self.debug_log_level = debug_log_level

    def clean(self, timeout = 0.05):
        """clean(timeout = 0.05)

        Removes all the buffered data from a tube by calling
        :meth:`pwnlib.tubes.tube.tube.recv` with a low timeout until it fails.
        """

        self.recvrepeat(timeout = timeout)

    def clean_and_log(self, timeout = 0.05):
        """clean_and_log(timeout = 0.05)

        Works exactly as :meth:`pwnlib.tubes.tube.tube.clean`, but logs recieved
        data with :meth:`pwnlib.log.info`.
        """

        if self.connected():
            log.info('Cleaning tube (fileno = %d):' % self.fileno())
            log.indented(self.recvrepeat(timeout = timeout))

    def connect_input(self, other):
        """connect_input(other)

        Connects the input of this tube to the output of another tube object."""

        def pump():
            import sys as _sys
            while True:
                if not (self.connected('send') and other.connected('recv')):
                    break

                try:
                    data = other.recv(timeout = 0.05)
                except EOFError:
                    break

                if not _sys:
                    return

                if data == None:
                    continue

                try:
                    self.send(data)
                except EOFError:
                    break

                if not _sys:
                    return

            self.shutdown('send')
            other.shutdown('recv')

        t = threading.Thread(target = pump)
        t.daemon = True
        t.start()

    def connect_output(self, other):
        """connect_output(other)

        Connects the output of this tube to the input of another tube object."""

        other.connect_input(self)

    def connect_both(self, other):
        """connect_both(other)

        Connects the both ends of this tube object with another tube object."""

        self.connect_input(other)
        self.connect_output(other)

    def spawn_process(self, *args, **kwargs):
        """Spawns a new process having this tube as stdin, stdout and stderr.

        Takes the same arguments as :class:`subprocess.Popen`."""

        subprocess.Popen(
            *args,
            stdin = self.fileno(),
            stdout = self.fileno(),
            stderr = self.fileno(),
            **kwargs
        )

    def __lshift__(self, other):
        self.connect_input(other)
        return other

    def __rshift__(self, other):
        self.connect_output(other)
        return other

    def __ne__(self, other):
        self << other << self

    def wait_for_close(self):
        """Waits until the tube is closed."""

        while self.connected():
            time.sleep(0.05)

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

    def shutdown(self, direction = "send"):
        """shutdown(direction = "send")

        Closes the tube for futher reading or writing depending on `direction`.

        Args:
          direction(str): Which direction to close; "in", "read" or "recv"
            closes the tube in the ingoing direction, "out", "write" or "send"
            closes it in the outgoing direction.

        Returns:
          :const:`None`
        """

        if   direction in ('in', 'read', 'recv'):
            direction = 'recv'
        elif direction in ('out', 'write', 'send'):
            direction = 'send'
        else:
            log.error('direction must be "in", "read" or "recv", or "out", "write" or "send"')

        self.shutdown_raw(direction)

    def connected(self, direction = 'any'):
        """connected(direction = 'any') -> bool

        Returns True if the tube is connected in the specified direction.

        Args:
          direction(str): Can be the string 'any', 'in', 'read', 'recv',
                          'out', 'write', 'send'.
        """

        if   direction in ('in', 'read', 'recv'):
            direction = 'recv'
        elif direction in ('out', 'write', 'send'):
            direction = 'send'
        elif direction == 'any':
            pass
        else:
            log.error('direction must be "any", "in", "read" or "recv", or "out", "write" or "send"')

        return self.connected_raw(direction)

    def __enter__(self):
        """Permit use of 'with' to control scoping and closing sessions.

        >>> shell = ssh(host='bandit.labs.overthewire.org',user='bandit0',password='bandit0') # doctest: +SKIP
        >>> with shell.run('bash') as s:  # doctest: +SKIP
        ...     s.sendline('echo helloworld; exit;')
        ...     print 'helloworld' in s.recvall()
        ...
        True
        """
        return self

    def __exit__(self, type, value, traceback):
        """Handles closing for 'with' statement"""
        self.close()

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

        Should not be called directly. Sends data to the tube.

        Should return :exc:`exceptions.EOFError`, if it is unable to send any
        more, because of a close tube.
        """

        log.bug('Should be implemented by a subclass.')

    def settimeout_raw(self, timeout):
        """settimeout_raw(timeout)

        Should not be called directly. Sets the timeout for
        the tube.
        """

        log.bug('Should be implemented by a subclass.')

    def can_recv_raw(self, timeout):
        """can_recv_raw(timeout) -> bool

        Should not be called directly. Returns True, if
        there is data available within the timeout, but
        ignores the buffer on the object.
        """

        log.bug('Should be implemented by a subclass.')

    def connected_raw(self, direction):
        """connected(direction = 'any') -> bool

        Should not be called directly.  Returns True iff the
        tube is connected in the given direction.
        """

        log.bug('Should be implemented by a subclass.')

    def close(self):
        """close()

        Closes the tube.
        """

        log.bug('Should be implemented by a subclass.')

    def fileno(self):
        """fileno() -> int

        Returns the file number used for reading.
        """

        log.bug('Should be implemented by a subclass.')

    def shutdown_raw(self, direction):
        """shutdown_raw(direction)

        Should not be called directly.  Closes the tube for further reading or
        writing.
        """

        log.bug('Should be implemented by a subclass.')
