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

    def __init__(self, timeout):
        self.buffer          = []
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
        if self.buffer:
            data = []
            n = 0
            while self.buffer and n < numb:
                s = self.buffer.pop()
                data.append(s)
                n += len(s)
            if n < numb:
                try:
                    s = self._recv(numb - n, timeout = 0)
                    if s != None:
                        data.append(s)
                except EOFError:
                    pass
            elif n > numb:
                s = data.pop()
                delta = n - numb
                self.buffer.append(s[delta:])
                data.append(s[:delta])
            return ''.join(data)

        return self._recv(numb, timeout = timeout)

    def _recv(self, numb = 4096, timeout = 'default'):
        """_recv(numb = 4096, timeout = 'default') -> str

        Recieves one chunk of from the internal buffer or from the OS if the
        buffer is empty.
        """
        # If there is already data, go with that
        if self.buffer:
            data = self.buffer.pop()
        else:
            if timeout == 'default':
                data = self.recv_raw(4096)
            else:
                timeout       = _fix_timeout(timeout, self.timeout)
                old_timeout   = self.timeout
                self.settimeout(timeout)
                data = self.recv_raw(4096)
                self.settimeout(old_timeout)

            if data == None:
                log.debug('Timed out')
                return None
            else:
                if context.log_level <= log_levels.DEBUG:
                    for line in data.splitlines(True):
                        log.debug('Received: %r' % line)

        if len(data) > numb:
            self.buffer.append(data[numb:])
            data = data[:numb]

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

        data = ''

        try:
            while not pred(data):
                res = self._recv(1, timeout)

                if res == None:
                    self.buffer.append(data)
                    return None

                data += res
        except:
            self.buffer.append(data)
            raise

        return data

    def recvn(self, numb, timeout = 'default'):
        """recvn(numb, timeout = 'default') -> str

        Recieves exactly `n` bytes.
        """

        data = []
        n = 0
        while n < numb:
            try:
                res = self._recv(timeout = timeout)
                if res == None:
                    self.buffer.extend(data)
                    return None
            except:
                self.buffer.extend(data)
                raise
            n += len(res)
            data.append(res)

        if numb < n:
            s = data.pop()
            delta = len(s) - (n - numb)
            self.buffer.append(s[delta:])
            data.append(s[:delta])

        return ''.join(data)

    def recvuntil(self, delims, timeout = 'default'):
        """recvuntil(delims, timeout = 'default') -> str

        Continue recieving until the recieved data ends with one of `delims`.

        As a shorthand, ``delim`` may be used instead of ``(delim, )``.
        """

        if not hasattr(delims, '__iter__'):
            delims = (delims,)

        delimslen = max(len(delim) for delim in delims)

        data = ''
        i = 0
        while True:

            try:
                res = self._recv(timeout = timeout)
                if res == None:
                    self.buffer.append(data)
                    return None
            except:
                self.buffer.append(data)
                raise

            data += res

            for delim in delims:
                j = data.find(delim, i)
                if j > -1:
                    j += len(delim)
                    data, rest = data[:j], data[j:]
                    self.buffer.append(rest)
                    return data
            if len(data) > delimslen:
                i = len(data) - delimslen + 1

    def recvlines(self, numlines, keepends = False, timeout = 'default'):
        """recvlines(numlines, keepends = False) -> str list

        Recieve `numlines` lines.  The lines are returned as a list.

        Line breaks are not included unless `keepends` is set to :const:`True`.
        """
        data = []
        for _ in xrange(numlines):
            try:
                res = self.recvuntil('\n', timeout = timeout)
                if res == None:
                    self.buffer.extend(data)
                    return None
            except:
                self.buffer.extend(data)
                raise
            data.append(res)

        if keepends:
            return data

        return [line[:-1] for line in data]

    def recvline(self, delims = None, keepend = False, timeout = 'default'):
        """recvline(delims = None, keepend = False) -> str

        If `delims` is :const:`None`, then recieve and return exactly one line.
        Otherwise, keep recieving lines until one is found which contains at
        least of `delims`.  The last line recieved will be returned.

        As a shorthand, ``delim`` may be used instead of ``(delim, )``.

        Only includes the line break if `keepend` is set to :const:`True`.
        """
        if delims == None:
            res = self.recvlines(1, keepends = keepend, timeout = timeout)
            if res == None:
                return None
            return res[0]

        if not hasattr(delims, '__iter__'):
            delims = (delims,)

        data = []
        while True:
            try:
                res = self.recvuntil('\n', timeout = timeout)
                if res == None:
                    self.buffer.extend(data)
                    return None
            except:
                self.buffer.extend(data)
                raise
            if any(delim in res for delim in delims):
                break
            data.append(res)

        if keepend:
            return res

        return res[:-1]

    def recvline_pred(self, pred, keepend = False, timeout = 'default'):
        """recvline_pred(pred, keepend = False) -> str

        Keep recieving lines until one, ``line``, is found such that
        ``bool(pred(line)) == True``.  Returns the last line recieved.

        Only includes the line break if `keepend` is set to :const:`True`.
        """

        data = []
        while True:
            try:
                res = self.recvuntil('\n', timeout = timeout)
                if res == None:
                    self.buffer.extend(data)
                    return None
                if pred(res):
                    break
            except:
                self.buffer.extend(data)
                raise
            data.append(res)

        if keepend:
            return res

        return res[:-1]

    def recvline_startswith(self, delims, keepend = False, timeout = 'default'):
        """recvline_startswith(delims, keepend = False) -> str

        Keep recieving lines until one is found that starts with one of
        `delims`.  Returns the last line recieved.

        As a shorthand, ``delim`` may be used instead of ``(delim, )``.

        Only includes the line break if `keepend` is set to :const:`True`.
        """

        if not hasattr(delims, '__iter__'):
            delims = (delims,)

        data = []
        while True:
            try:
                res = self.recvuntil('\n', timeout = timeout)
                if res == None:
                    self.buffer.extend(data)
                    return None
            except:
                self.buffer.extend(data)
                raise
            if any(res.startswith(delim) for delim in delims):
                break
            data.append(res)

        if keepend:
            return res

        return res[:-1]

    def recvline_endswith(self, delims, keepend = False, timeout = 'default'):
        """recvline_endswith(delims, keepend = False) -> str

        Keep recieving lines until one is found that ends with one of `delims`.
        Returns the last line recieved.

        As a shorthand, ``delim`` may be used instead of ``(delim, )``.

        Only includes the line break if `keepend` is set to :const:`True`.
        """

        if not hasattr(delims, '__iter__'):
            delims = (delims,)

        data = []
        while True:
            try:
                res = self.recvuntil('\n', timeout = timeout)
                if res == None:
                    self.buffer.extend(data)
                    return None
            except:
                self.buffer.extend(data)
                raise
            if any(res.endswith(delim) for delim in delims):
                break
            data.append(res)

        if keepend:
            return res

        return res[:-1]

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

        return self.recvpred(pred, timeout = timeout)

    def recvline_regex(self, regex, exact = False, keepend = False,
                       eout = 'default'):
        """recvregex(regex, exact = False, keepend = False,
                     timeout = 'default') -> str

        Wrapper around :func:`recvline_pred`, which will return when a regex
        matches a line.

        By default :func:`re.RegexObject.search` is used, but if `exact` is
        set to True, then :func:`re.RegexObject.match` will be used instead.
        """

        if isinstance(regex, (str, unicode)):
            regex = re.compile(regex)

        if exact:
            pred = regex.match
        else:
            pred = regex.search

        return self.recvline_pred(pred, keepend = keepend, timeout = timeout)

    def recvrepeat(self, timeout = 'default'):
        """recvrepeat()

        Receives data until a timeout or EOF is reached.
        """

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

        h = log.waitfor('Recieving all data')

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

        if context.log_level <= log_levels.DEBUG:
            for line in data.splitlines(True):
                log.debug('Received: %r' % line)
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

        log.info('Switching to interactive mode')

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
                    log.info('Got EOF while reading in interactive')
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
                        log.info('Got EOF while sending in interactive')
                else:
                    go[0] = False
        except KeyboardInterrupt:
            log.info('Interrupted')

        while t.is_alive():
            t.join(timeout = 0.1)

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
