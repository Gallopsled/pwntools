# -*- coding: utf-8 -*-
import logging
import re
import string
import subprocess
import sys
import threading
import time

from .. import atexit
from .. import term
from ..context import context
from ..log import Logger
from ..timeout import Timeout
from ..util import fiddling
from ..util import misc
from ..util import packing
from .buffer import Buffer


class tube(Timeout, Logger):
    """
    Container of all the tube functions common to sockets, TTYs and SSH connetions.
    """

    default = Timeout.default
    forever = Timeout.forever

    #: Delimiter to use for :meth:`sendline`, :meth:`recvline`,
    #: and related functions.
    newline = '\n'

    def __init__(self, timeout = default, level = None):
        super(tube, self).__init__(timeout)

        Logger.__init__(self, None)
        if level is not None:
            self.setLevel(level)

        self.buffer          = Buffer()
        atexit.register(self.close)

    # Functions based on functions from subclasses
    def recv(self, numb = 4096, timeout = default):
        r"""recv(numb = 4096, timeout = default) -> str

        Receives up to `numb` bytes of data from the tube, and returns
        as soon as any quantity of data is available.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        Raises:
            exceptions.EOFError: The connection is closed

        Returns:
            A string containing bytes received from the socket,
            or ``''`` if a timeout occurred while waiting.

        Examples:

            >>> t = tube()
            >>> # Fake a data source
            >>> t.recv_raw = lambda n: 'Hello, world'
            >>> t.recv() == 'Hello, world'
            True
            >>> t.unrecv('Woohoo')
            >>> t.recv() == 'Woohoo'
            True
            >>> with context.local(log_level='debug'):
            ...    _ = t.recv() # doctest: +ELLIPSIS
            [...] Received 0xc bytes:
                'Hello, world'
        """
        return self._recv(numb, timeout) or ''

    def unrecv(self, data):
        """unrecv(data)

        Puts the specified data back at the beginning of the receive
        buffer.

        Examples:

            .. doctest::

                >>> t = tube()
                >>> t.recv_raw = lambda n: 'hello'
                >>> t.recv()
                'hello'
                >>> t.recv()
                'hello'
                >>> t.unrecv('world')
                >>> t.recv()
                'world'
                >>> t.recv()
                'hello'
        """
        self.buffer.unget(data)

    def _fillbuffer(self, timeout = default):
        """_fillbuffer(timeout = default)

        Fills the internal buffer from the pipe, by calling
        :meth:`recv_raw` exactly once.

        Returns:

            The bytes of data received, or ``''`` if no data was received.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda *a: 'abc'
            >>> len(t.buffer)
            0
            >>> t._fillbuffer()
            'abc'
            >>> len(t.buffer)
            3
        """
        data = ''

        with self.local(timeout):
            data = self.recv_raw(4096)

        if data and self.isEnabledFor(logging.DEBUG):
            self.debug('Received %#x bytes:' % len(data))

            if len(set(data)) == 1 and len(data) > 1:
                self.indented('%r * %#x' % (data[0], len(data)), level = logging.DEBUG)
            elif all(c in string.printable for c in data):
                for line in data.splitlines(True):
                    self.indented(repr(line), level = logging.DEBUG)
            else:
                self.indented(fiddling.hexdump(data), level = logging.DEBUG)

        if data:
            self.buffer.add(data)

        return data


    def _recv(self, numb = 4096, timeout = default):
        """_recv(numb = 4096, timeout = default) -> str

        Receives one chunk of from the internal buffer or from the OS if the
        buffer is empty.
        """
        data = ''

        # No buffered data, could not put anything in the buffer
        # before timeout.
        if not self.buffer and not self._fillbuffer(timeout):
            return ''

        return self.buffer.get(numb)

    def recvpred(self, pred, timeout = default):
        """recvpred(pred, timeout = default) -> str

        Receives one byte at a time from the tube, until ``pred(bytes)``
        evaluates to True.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        Arguments:
            pred(callable): Function to call, with the currently-accumulated data.
            timeout(int): Timeout for the operation

        Raises:
            exceptions.EOFError: The connection is closed

        Returns:
            A string containing bytes received from the socket,
            or ``''`` if a timeout occurred while waiting.
        """

        data = ''

        with self.countdown(timeout):
            while not pred(data):
                try:
                    res = self.recv(1)
                except Exception:
                    self.unrecv(data)
                    return ''

                if res:
                    data += res
                else:
                    self.unrecv(data)
                    return ''

        return data

    def recvn(self, numb, timeout = default):
        """recvn(numb, timeout = default) -> str

        Receives exactly `n` bytes.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        Raises:
            exceptions.EOFError: The connection closed before the request could be satisfied

        Returns:
            A string containing bytes received from the socket,
            or ``''`` if a timeout occurred while waiting.

        Examples:

            .. doctest::

                >>> t = tube()
                >>> data = 'hello world'
                >>> t.recv_raw = lambda *a: data
                >>> t.recvn(len(data)) == data
                True
                >>> t.recvn(len(data)+1) == data + data[0]
                True
                >>> t.recv_raw = lambda *a: None
                >>> # The remaining data is buffered
                >>> t.recv() == data[1:]
                True
                >>> t.recv_raw = lambda *a: time.sleep(0.01) or 'a'
                >>> t.recvn(10, timeout=0.05)
                ''
                >>> t.recvn(10, timeout=0.06) # doctest: +ELLIPSIS
                'aaaaaa...'
        """
        # Keep track of how much data has been received
        # It will be pasted together at the end if a
        # timeout does not occur, or put into the tube buffer.
        with self.countdown(timeout):
            while self.countdown_active() and len(self.buffer) < numb and self._fillbuffer(self.timeout):
                pass

        if len(self.buffer) < numb:
            return ''

        return self.buffer.get(numb)

    def recvuntil(self, delims, drop=False, timeout = default):
        """recvuntil(delims, timeout = default) -> str

        Receive data until one of `delims` is encountered.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        arguments:
            delims(str,tuple): String of delimiters characters, or list of delimiter strings.
            drop(bool): Drop the ending.  If ``True`` it is removed from the end of the return value.

        Raises:
            exceptions.EOFError: The connection closed before the request could be satisfied

        Returns:
            A string containing bytes received from the socket,
            or ``''`` if a timeout occurred while waiting.

        Examples:

            .. doctest::

                >>> t = tube()
                >>> t.recv_raw = lambda n: "Hello World!"
                >>> t.recvuntil(' ')
                'Hello '
                >>> _=t.clean(0)
                >>> # Matches on 'o' in 'Hello'
                >>> t.recvuntil(tuple(' Wor'))
                'Hello'
                >>> _=t.clean(0)
                >>> # Matches expressly full string
                >>> t.recvuntil(' Wor')
                'Hello Wor'
                >>> _=t.clean(0)
                >>> # Matches on full string, drops match
                >>> t.recvuntil(' Wor', drop=True)
                'Hello'

                >>> # Try with regex special characters
                >>> t = tube()
                >>> t.recv_raw = lambda n: "Hello|World"
                >>> t.recvuntil('|', drop=True)
                'Hello'

        """
        # Convert string into singleton tupple
        if isinstance(delims, (str, unicode)):
            delims = (delims,)

        # Longest delimiter for tracking purposes
        longest = max(map(len, delims))

        # Cumulative data to search
        data = []
        top = ''

        with self.countdown(timeout):
            while self.countdown_active():
                try:
                    res = self.recv(timeout=self.timeout)
                except Exception:
                    self.unrecv(''.join(data) + top)
                    raise

                if not res:
                    self.unrecv(''.join(data) + top)
                    return ''

                top += res
                start = len(top)
                for d in delims:
                    j = top.find(d)
                    if start > j > -1:
                        start = j
                        end = j + len(d)
                if start < len(top):
                    self.unrecv(top[end:])
                    if drop:
                        top = top[:start]
                    else:
                        top = top[:end]
                    return ''.join(data) + top
                if len(top) > longest:
                    i = -longest - 1
                    data.append(top[:i])
                    top = top[i:]

        return ''

    def recvlines(self, numlines=2**20, keepends = False, timeout = default):
        r"""recvlines(numlines, keepends = False, timeout = default) -> str list

        Receive up to ``numlines`` lines.

        A "line" is any sequence of bytes terminated by the byte sequence
        set by :attr:`newline`, which defaults to ``'\n'``.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        Arguments:
            numlines(int): Maximum number of lines to receive
            keepends(bool): Keep newlines at the end of each line (``False``).
            timeout(int): Maximum timeout

        Raises:
            exceptions.EOFError: The connection closed before the request could be satisfied

        Returns:
            A string containing bytes received from the socket,
            or ``''`` if a timeout occurred while waiting.

        Examples:

            .. doctest::

                >>> t = tube()
                >>> t.recv_raw = lambda n: '\n'
                >>> t.recvlines(3)
                ['', '', '']
                >>> t.recv_raw = lambda n: 'Foo\nBar\nBaz\n'
                >>> t.recvlines(3)
                ['Foo', 'Bar', 'Baz']
                >>> t.recvlines(3, True)
                ['Foo\n', 'Bar\n', 'Baz\n']
        """
        lines = []
        with self.countdown(timeout):
            for _ in xrange(numlines):
                try:
                    # We must set 'keepends' to True here so that we can
                    # restore the original, unmodified data to the buffer
                    # in the event of a timeout.
                    res = self.recvline(keepends=True, timeout=timeout)
                except Exception:
                    self.unrecv(''.join(lines))
                    raise

                if res:
                    lines.append(res)
                else:
                    break

        if not keepends:
            lines = [line.rstrip(self.newline) for line in lines]

        return lines

    def recvline(self, keepends = True, timeout = default):
        r"""recvline(keepends = True) -> str

        Receive a single line from the tube.

        A "line" is any sequence of bytes terminated by the byte sequence
        set in :attr:`newline`, which defaults to ``'\n'``.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        Arguments:
            keepends(bool): Keep the line ending (``True``).
            timeout(int): Timeout

        Return:
            All bytes received over the tube until the first
            newline ``'\n'`` is received.  Optionally retains
            the ending.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: 'Foo\nBar\r\nBaz\n'
            >>> t.recvline()
            'Foo\n'
            >>> t.recvline()
            'Bar\r\n'
            >>> t.recvline(keepends = False)
            'Baz'
            >>> t.newline = '\r\n'
            >>> t.recvline(keepends = False)
            'Foo\nBar'
        """
        return self.recvuntil(self.newline, drop = not keepends, timeout = timeout)

    def recvline_pred(self, pred, keepends = False, timeout = default):
        r"""recvline_pred(pred, keepends = False) -> str

        Receive data until ``pred(line)`` returns a truthy value.
        Drop all other data.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        Arguments:
            pred(callable): Function to call.  Returns the line for which
                this function returns ``True``.

        Examples:

            .. doctest::

                >>> t = tube()
                >>> t.recv_raw = lambda n: "Foo\nBar\nBaz\n"
                >>> t.recvline_pred(lambda line: line == "Bar\n")
                'Bar'
                >>> t.recvline_pred(lambda line: line == "Bar\n", keepends=True)
                'Bar\n'
                >>> t.recvline_pred(lambda line: line == 'Nope!', timeout=0.1)
                ''
        """

        tmpbuf = Buffer()
        line   = ''
        with self.countdown(timeout):
            while self.countdown_active():
                try:
                    line = self.recvline(keepends=True)
                except Exception:
                    self.buffer.add(tmpbuf)
                    raise

                if not line:
                    self.buffer.add(tmpbuf)
                    return ''

                if pred(line):
                    if not keepends:
                        line = line[:-len(self.newline)]
                    return line
                else:
                    tmpbuf.add(line)

        return ''

    def recvline_contains(self, items, keepends = False, timeout = default):
        r"""
        Receive lines until one line is found which contains at least
        one of `items`.

        Arguments:
            items(str,tuple): List of strings to search for, or a single string.
            keepends(bool): Return lines with newlines if ``True``
            timeout(int): Timeout, in seconds

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: "Hello\nWorld\nXylophone\n"
            >>> t.recvline_contains('r')
            'World'
            >>> f = lambda n: "cat dog bird\napple pear orange\nbicycle car train\n"
            >>> t = tube()
            >>> t.recv_raw = f
            >>> t.recvline_contains('pear')
            'apple pear orange'
            >>> t = tube()
            >>> t.recv_raw = f
            >>> t.recvline_contains(('car', 'train'))
            'bicycle car train'
        """
        if isinstance(items, (str,unicode)):
            items = (items,)

        def pred(line):
            return any(d in line for d in items)

        return self.recvline_pred(pred, keepends, timeout)

    def recvline_startswith(self, delims, keepends = False, timeout = default):
        r"""recvline_startswith(delims, keepends = False, timeout = default) -> str

        Keep receiving lines until one is found that starts with one of
        `delims`.  Returns the last line received.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        Arguments:
            delims(str,tuple): List of strings to search for, or string of single characters
            keepends(bool): Return lines with newlines if ``True``
            timeout(int): Timeout, in seconds

        Returns:
            The first line received which starts with a delimiter in ``delims``.

        Examples:

            .. doctest::

                >>> t = tube()
                >>> t.recv_raw = lambda n: "Hello\nWorld\nXylophone\n"
                >>> t.recvline_startswith(tuple('WXYZ'))
                'World'
                >>> t.recvline_startswith(tuple('WXYZ'), True)
                'Xylophone\n'
                >>> t.recvline_startswith('Wo')
                'World'
        """
        # Convert string into singleton tupple
        if isinstance(delims, (str, unicode)):
            delims = (delims,)

        return self.recvline_pred(lambda line: any(map(line.startswith, delims)),
                                  keepends=keepends,
                                  timeout=timeout)

    def recvline_endswith(self, delims, keepends = False, timeout = default):
        r"""recvline_endswith(delims, keepends = False, timeout = default) -> str

        Keep receiving lines until one is found that starts with one of
        `delims`.  Returns the last line received.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        See :meth:`recvline_startswith` for more details.

        Examples:

            .. doctest::

                >>> t = tube()
                >>> t.recv_raw = lambda n: 'Foo\nBar\nBaz\nKaboodle\n'
                >>> t.recvline_endswith('r')
                'Bar'
                >>> t.recvline_endswith(tuple('abcde'), True)
                'Kaboodle\n'
                >>> t.recvline_endswith('oodle')
                'Kaboodle'
        """
        # Convert string into singleton tupple
        if isinstance(delims, (str, unicode)):
            delims = (delims,)

        delims = tuple(delim + self.newline for delim in delims)

        return self.recvline_pred(lambda line: any(map(line.endswith, delims)),
                                  keepends=keepends,
                                  timeout=timeout)

    def recvregex(self, regex, exact = False, timeout = default):
        """recvregex(regex, exact = False, timeout = default) -> str

        Wrapper around :func:`recvpred`, which will return when a regex
        matches the string in the buffer.

        By default :func:`re.RegexObject.search` is used, but if `exact` is
        set to True, then :func:`re.RegexObject.match` will be used instead.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.
        """

        if isinstance(regex, (str, unicode)):
            regex = re.compile(regex)

        if exact:
            pred = regex.match
        else:
            pred = regex.search

        return self.recvpred(pred, timeout = timeout)

    def recvline_regex(self, regex, exact = False, keepends = False, timeout = default):
        """recvregex(regex, exact = False, keepends = False, timeout = default) -> str

        Wrapper around :func:`recvline_pred`, which will return when a regex
        matches a line.

        By default :func:`re.RegexObject.search` is used, but if `exact` is
        set to True, then :func:`re.RegexObject.match` will be used instead.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.
        """

        if isinstance(regex, (str, unicode)):
            regex = re.compile(regex)

        if exact:
            pred = regex.match
        else:
            pred = regex.search

        return self.recvline_pred(pred, keepends = keepends, timeout = timeout)

    def recvrepeat(self, timeout = default):
        """recvrepeat()

        Receives data until a timeout or EOF is reached.

        Examples:

            >>> data = [
            ... 'd',
            ... '', # simulate timeout
            ... 'c',
            ... 'b',
            ... 'a',
            ... ]
            >>> def delayrecv(n, data=data):
            ...     return data.pop()
            >>> t = tube()
            >>> t.recv_raw = delayrecv
            >>> t.recvrepeat(0.2)
            'abc'
            >>> t.recv()
            'd'
        """

        try:
            while self._fillbuffer(timeout=timeout):
                pass
        except EOFError:
            pass

        return self.buffer.get()

    def recvall(self, timeout=Timeout.forever):
        """recvall() -> str

        Receives data until EOF is reached.
        """

        with self.waitfor('Receiving all data') as h:
            l = len(self.buffer)
            with self.local(timeout):
                try:
                    while True:
                        l = misc.size(len(self.buffer))
                        h.status(l)
                        if not self._fillbuffer():
                            break
                except EOFError:
                    pass
            h.success("Done (%s)" % l)
        self.close()

        return self.buffer.get()

    def send(self, data):
        """send(data)

        Sends data.

        If log level ``DEBUG`` is enabled, also prints out the data
        received.

        If it is not possible to send anymore because of a closed
        connection, it raises ``exceptions.EOFError``

        Examples:

            >>> def p(x): print repr(x)
            >>> t = tube()
            >>> t.send_raw = p
            >>> t.send('hello')
            'hello'
        """

        if self.isEnabledFor(logging.DEBUG):
            self.debug('Sent %#x bytes:' % len(data))
            if len(set(data)) == 1:
                self.indented('%r * %#x' % (data[0], len(data)))
            elif all(c in string.printable for c in data):
                for line in data.splitlines(True):
                    self.indented(repr(line), level = logging.DEBUG)
            else:
                self.indented(fiddling.hexdump(data), level = logging.DEBUG)
        self.send_raw(data)

    def sendline(self, line=''):
        r"""sendline(data)

        Shorthand for ``t.send(data + t.newline)``.

        Examples:

            >>> def p(x): print repr(x)
            >>> t = tube()
            >>> t.send_raw = p
            >>> t.sendline('hello')
            'hello\n'
            >>> t.newline = '\r\n'
            >>> t.sendline('hello')
            'hello\r\n'
        """

        self.send(line + self.newline)

    def sendlines(self, lines=[]):
        for line in lines:
            self.sendline(line)

    def sendafter(self, delim, data, timeout = default):
        """sendafter(delim, data, timeout = default) -> str

        A combination of ``recvuntil(delim, timeout)`` and ``send(data)``.
        """

        res = self.recvuntil(delim, timeout)
        self.send(data)
        return res

    def sendlineafter(self, delim, data, timeout = default):
        """sendlineafter(delim, data, timeout = default) -> str

        A combination of ``recvuntil(delim, timeout)`` and ``sendline(data)``."""

        res = self.recvuntil(delim, timeout)
        self.sendline(data)
        return res

    def sendthen(self, delim, data, timeout = default):
        """sendthen(delim, data, timeout = default) -> str

        A combination of ``send(data)`` and ``recvuntil(delim, timeout)``."""

        self.send(data)
        return self.recvuntil(delim, timeout)

    def sendlinethen(self, delim, data, timeout = default):
        """sendlinethen(delim, data, timeout = default) -> str

        A combination of ``sendline(data)`` and ``recvuntil(delim, timeout)``."""

        self.send(data + self.newline)
        return self.recvuntil(delim, timeout)

    def interactive(self, prompt = term.text.bold_red('$') + ' '):
        """interactive(prompt = pwnlib.term.text.bold_red('$') + ' ')

        Does simultaneous reading and writing to the tube. In principle this just
        connects the tube to standard in and standard out, but in practice this
        is much more usable, since we are using :mod:`pwnlib.term` to print a
        floating prompt.

        Thus it only works in while in :data:`pwnlib.term.term_mode`.
        """

        self.info('Switching to interactive mode')

        go = threading.Event()
        def recv_thread():
            while not go.isSet():
                try:
                    cur = self.recv(timeout = 0.05)
                    cur = cur.replace('\r\n', '\n')
                    if cur:
                        sys.stdout.write(cur)
                        sys.stdout.flush()
                except EOFError:
                    self.info('Got EOF while reading in interactive')
                    break

        t = context.Thread(target = recv_thread)
        t.daemon = True
        t.start()

        try:
            while not go.isSet():
                if term.term_mode:
                    data = term.readline.readline(prompt = prompt, float = True)
                else:
                    data = sys.stdin.read(1)

                if data:
                    try:
                        self.send(data)
                    except EOFError:
                        go.set()
                        self.info('Got EOF while sending in interactive')
                else:
                    go.set()
        except KeyboardInterrupt:
            self.info('Interrupted')
            go.set()

        while t.is_alive():
            t.join(timeout = 0.1)

    def stream(self, line_mode=True):
        """stream()

        Receive data until the tube exits, and print it to stdout.

        Similar to :func:`interactive`, except that no input is sent.

        Similar to ``print tube.recvall()`` except that data is printed
        as it is received, rather than after all data is received.

        Arguments:
            line_mode(bool): Whether to receive line-by-line or raw data.

        Returns:
            All data printed.
        """
        buf = Buffer()
        function = self.recvline if line_mode else self.recv
        try:
            while True:
                buf.add(function())
                sys.stdout.write(buf.data[-1])
        except KeyboardInterrupt:
            pass
        except EOFError:
            pass

        return buf.get()

    def clean(self, timeout = 0.05):
        """clean(timeout = 0.05)

        Removes all the buffered data from a tube by calling
        :meth:`pwnlib.tubes.tube.tube.recv` with a low timeout until it fails.

        If ``timeout`` is zero, only cached data will be cleared.

        Note: If timeout is set to zero, the underlying network is
        not actually polled; only the internal buffer is cleared.

        Returns:

            All data received

        Examples:

            >>> t = tube()
            >>> t.unrecv('clean me up')
            >>> t.clean(0)
            'clean me up'
            >>> len(t.buffer)
            0
        """
        if timeout == 0:
            return self.buffer.get()

        return self.recvrepeat(timeout)

    def clean_and_log(self, timeout = 0.05):
        r"""clean_and_log(timeout = 0.05)

        Works exactly as :meth:`pwnlib.tubes.tube.tube.clean`, but logs received
        data with :meth:`pwnlib.self.info`.

        Returns:

            All data received

        Examples:

            >>> def recv(n, data=['', 'hooray_data']):
            ...     while data: return data.pop()
            >>> t = tube()
            >>> t.recv_raw      = recv
            >>> t.connected_raw = lambda d: True
            >>> t.fileno        = lambda: 1234
            >>> with context.local(log_level='info'):
            ...     data = t.clean_and_log() #doctest: +ELLIPSIS
            [DEBUG] Received 0xb bytes:
                'hooray_data'
            >>> data
            'hooray_data'
            >>> context.clear()
        """
        with context.local(log_level='debug'):
            return self.clean(timeout)

    def connect_input(self, other):
        """connect_input(other)

        Connects the input of this tube to the output of another tube object.


        Examples:

            >>> def p(x): print x
            >>> def recvone(n, data=['data']):
            ...     while data: return data.pop()
            ...     raise EOFError
            >>> a = tube()
            >>> b = tube()
            >>> a.recv_raw = recvone
            >>> b.send_raw = p
            >>> a.connected_raw = lambda d: True
            >>> b.connected_raw = lambda d: True
            >>> a.shutdown      = lambda d: True
            >>> b.shutdown      = lambda d: True
            >>> import time
            >>> _=(b.connect_input(a), time.sleep(0.1))
            data
        """

        def pump():
            import sys as _sys
            while self.countdown_active():
                if not (self.connected('send') and other.connected('recv')):
                    break

                try:
                    data = other.recv(timeout = 0.05)
                except EOFError:
                    break

                if not _sys:
                    return

                if not data:
                    continue

                try:
                    self.send(data)
                except EOFError:
                    break

                if not _sys:
                    return

            self.shutdown('send')
            other.shutdown('recv')

        t = context.Thread(target = pump)
        t.daemon = True
        t.start()

    def connect_output(self, other):
        """connect_output(other)

        Connects the output of this tube to the input of another tube object.

        Examples:

            >>> def p(x): print x
            >>> def recvone(n, data=['data']):
            ...     while data: return data.pop()
            ...     raise EOFError
            >>> a = tube()
            >>> b = tube()
            >>> a.recv_raw = recvone
            >>> b.send_raw = p
            >>> a.connected_raw = lambda d: True
            >>> b.connected_raw = lambda d: True
            >>> a.shutdown      = lambda d: True
            >>> b.shutdown      = lambda d: True
            >>> _=(a.connect_output(b), time.sleep(0.1))
            data
        """

        other.connect_input(self)

    def connect_both(self, other):
        """connect_both(other)

        Connects the both ends of this tube object with another tube object."""

        self.connect_input(other)
        self.connect_output(other)

    def spawn_process(self, *args, **kwargs):
        """Spawns a new process having this tube as stdin, stdout and stderr.

        Takes the same arguments as :class:`subprocess.Popen`."""

        return subprocess.Popen(
            *args,
            stdin = self.fileno(),
            stdout = self.fileno(),
            stderr = self.fileno(),
            **kwargs
        )

    def __lshift__(self, other):
        """
        Shorthand for connecting multiple tubes.

        See :meth:`connect_input` for more information.

        Examples:

            The following are equivalent ::

                tube_a >> tube.b
                tube_a.connect_input(tube_b)

            This is useful when chaining multiple tubes ::

                tube_a >> tube_b >> tube_a
                tube_a.connect_input(tube_b)
                tube_b.connect_input(tube_a)
        """
        self.connect_input(other)
        return other

    def __rshift__(self, other):
        """
        Inverse of the ``<<`` operator.  See :meth:`__lshift__`.

        See :meth:`connect_input` for more information.
        """
        self.connect_output(other)
        return other

    def __ne__(self, other):
        """
        Shorthand for connecting tubes to eachother.

        The following are equivalent ::

            a >> b >> a
            a <> b

        See :meth:`connect_input` for more information.
        """
        self << other << self

    def wait_for_close(self):
        """Waits until the tube is closed."""

        while self.connected():
            time.sleep(0.05)

    wait = wait_for_close

    def can_recv(self, timeout = 0):
        """can_recv(timeout = 0) -> bool

        Returns True, if there is data available within `timeout` seconds.

        Examples:

            >>> import time
            >>> t = tube()
            >>> t.can_recv_raw = lambda *a: False
            >>> t.can_recv()
            False
            >>> _=t.unrecv('data')
            >>> t.can_recv()
            True
            >>> _=t.recv()
            >>> t.can_recv()
            False
        """

        return bool(self.buffer or self.can_recv_raw(timeout))

    def settimeout(self, timeout):
        """settimeout(timeout)

        Set the timeout for receiving operations. If the string "default"
        is given, then :data:`context.timeout` will be used. If None is given,
        then there will be no timeout.

        Examples:

            >>> t = tube()
            >>> t.settimeout_raw = lambda t: None
            >>> t.settimeout(3)
            >>> t.timeout == 3
            True
        """

        self.timeout = timeout


    shutdown_directions = {
        'in':    'recv',
        'read':  'recv',
        'recv':  'recv',
        'out':   'send',
        'write': 'send',
        'send':  'send',
    }

    connected_directions = shutdown_directions.copy()
    connected_directions['any'] = 'any'

    def shutdown(self, direction = "send"):
        """shutdown(direction = "send")

        Closes the tube for futher reading or writing depending on `direction`.

        Arguments:
          direction(str): Which direction to close; "in", "read" or "recv"
            closes the tube in the ingoing direction, "out", "write" or "send"
            closes it in the outgoing direction.

        Returns:
          :const:`None`

        Examples:

            >>> def p(x): print x
            >>> t = tube()
            >>> t.shutdown_raw = p
            >>> _=map(t.shutdown, ('in', 'read', 'recv', 'out', 'write', 'send'))
            recv
            recv
            recv
            send
            send
            send
            >>> t.shutdown('bad_value') #doctest: +ELLIPSIS
            Traceback (most recent call last):
            ...
            KeyError: "direction must be in ['in', 'out', 'read', 'recv', 'send', 'write']"
        """
        try:
            direction = self.shutdown_directions[direction]
        except KeyError:
            raise KeyError('direction must be in %r' % sorted(self.shutdown_directions))
        else:
            self.shutdown_raw(self.shutdown_directions[direction])

    def connected(self, direction = 'any'):
        """connected(direction = 'any') -> bool

        Returns True if the tube is connected in the specified direction.

        Arguments:
          direction(str): Can be the string 'any', 'in', 'read', 'recv',
                          'out', 'write', 'send'.

        Doctest:

            >>> def p(x): print x
            >>> t = tube()
            >>> t.connected_raw = p
            >>> _=map(t.connected, ('any', 'in', 'read', 'recv', 'out', 'write', 'send'))
            any
            recv
            recv
            recv
            send
            send
            send
            >>> t.connected('bad_value') #doctest: +ELLIPSIS
            Traceback (most recent call last):
            ...
            KeyError: "direction must be in ['any', 'in', 'out', 'read', 'recv', 'send', 'write']"
        """
        try:
            direction = self.connected_directions[direction]
        except KeyError:
            raise KeyError('direction must be in %r' % sorted(self.connected_directions))
        else:
            return self.connected_raw(direction)

    def __enter__(self):
        """Permit use of 'with' to control scoping and closing sessions.

        Examples:

            .. doctest::

                >>> t = tube()
                >>> def p(x): print x
                >>> t.close = lambda: p("Closed!")
                >>> with t: pass
                Closed!
        """
        return self

    def __exit__(self, type, value, traceback):
        """Handles closing for 'with' statement

        See :meth:`__enter__`
        """
        self.close()

    # The minimal interface to be implemented by a child
    def recv_raw(self, numb):
        """recv_raw(numb) -> str

        Should not be called directly. Receives data without using the buffer
        on the object.

        Unless there is a timeout or closed connection, this should always
        return data. In case of a timeout, it should return None, in case
        of a closed connection it should raise an ``exceptions.EOFError``.
        """

        raise EOFError('Not implemented')

    def send_raw(self, data):
        """send_raw(data)

        Should not be called directly. Sends data to the tube.

        Should return ``exceptions.EOFError``, if it is unable to send any
        more, because of a close tube.
        """

        raise EOFError('Not implemented')

    def settimeout_raw(self, timeout):
        """settimeout_raw(timeout)

        Should not be called directly. Sets the timeout for
        the tube.
        """

        raise NotImplementedError()

    def timeout_change(self):
        """
        Informs the raw layer of the tube that the timeout has changed.

        Should not be called directly.

        Inherited from :class:`Timeout`.
        """
        try:
            self.settimeout_raw(self.timeout)
        except NotImplementedError:
            pass

    def can_recv_raw(self, timeout):
        """can_recv_raw(timeout) -> bool

        Should not be called directly. Returns True, if
        there is data available within the timeout, but
        ignores the buffer on the object.
        """

        raise NotImplementedError()

    def connected_raw(self, direction):
        """connected(direction = 'any') -> bool

        Should not be called directly.  Returns True iff the
        tube is connected in the given direction.
        """

        raise NotImplementedError()

    def close(self):
        """close()

        Closes the tube.
        """
        pass
        # Ideally we could:
        # raise NotImplementedError()
        # But this causes issues with the unit tests.

    def fileno(self):
        """fileno() -> int

        Returns the file number used for reading.
        """

        raise NotImplementedError()

    def shutdown_raw(self, direction):
        """shutdown_raw(direction)

        Should not be called directly.  Closes the tube for further reading or
        writing.
        """

        raise NotImplementedError()

    #: Alias for :meth:`recv`
    def read(self, *a, **kw): return self.recv(*a, **kw)
    #: Alias for :meth:`recvpred`
    def readpred(self, *a, **kw): return self.recvpred(*a, **kw)
    #: Alias for :meth:`recvn`
    def readn(self, *a, **kw): return self.recvn(*a, **kw)
    #: Alias for :meth:`recvuntil`
    def readuntil(self, *a, **kw): return self.recvuntil(*a, **kw)
    #: Alias for :meth:`recvlines`
    def readlines(self, *a, **kw): return self.recvlines(*a, **kw)
    #: Alias for :meth:`recvline`
    def readline(self, *a, **kw): return self.recvline(*a, **kw)
    #: Alias for :meth:`recvline_pred`
    def readline_pred(self, *a, **kw): return self.recvline_pred(*a, **kw)
    #: Alias for :meth:`recvline_contains`
    def readline_contains(self, *a, **kw): return self.recvline_contains(*a, **kw)
    #: Alias for :meth:`recvline_startswith`
    def readline_startswith(self, *a, **kw): return self.recvline_startswith(*a, **kw)
    #: Alias for :meth:`recvline_endswith`
    def readline_endswith(self, *a, **kw): return self.recvline_endswith(*a, **kw)
    #: Alias for :meth:`recvregex`
    def readregex(self, *a, **kw): return self.recvregex(*a, **kw)
    #: Alias for :meth:`recvline_regex`
    def readline_regex(self, *a, **kw): return self.recvline_regex(*a, **kw)
    #: Alias for :meth:`recvrepeat`
    def readrepeat(self, *a, **kw): return self.recvrepeat(*a, **kw)
    #: Alias for :meth:`recvall`
    def readall(self, *a, **kw): return self.recvall(*a, **kw)

    #: Alias for :meth:`send`
    def write(self, *a, **kw): return self.send(*a, **kw)
    #: Alias for :meth:`sendline`
    def writeline(self, *a, **kw): return self.sendline(*a, **kw)
    #: Alias for :meth:`sendafter`
    def writeafter(self, *a, **kw): return self.sendafter(*a, **kw)
    #: Alias for :meth:`sendlineafter`
    def writelineafter(self, *a, **kw): return self.sendlineafter(*a, **kw)
    #: Alias for :meth:`sendthen`
    def writethen(self, *a, **kw): return self.sendthen(*a, **kw)
    #: Alias for :meth:`sendlinethen`
    def writelinethen(self, *a, **kw): return self.sendlinethen(*a, **kw)

    def p64(self, *a, **kw):        return self.send(packing.p64(*a, **kw))
    def p32(self, *a, **kw):        return self.send(packing.p32(*a, **kw))
    def p16(self, *a, **kw):        return self.send(packing.p16(*a, **kw))
    def p8(self, *a, **kw):         return self.send(packing.p8(*a, **kw))
    def pack(self, *a, **kw):       return self.send(packing.pack(*a, **kw))

    def u64(self, *a, **kw):        return packing.u64(self.recvn(8), *a, **kw)
    def u32(self, *a, **kw):        return packing.u32(self.recvn(4), *a, **kw)
    def u16(self, *a, **kw):        return packing.u16(self.recvn(2), *a, **kw)
    def u8(self, *a, **kw):         return packing.u8(self.recvn(1), *a, **kw)
    def unpack(self, *a, **kw):     return packing.unpack(self.recvn(context.bytes), *a, **kw)

    def flat(self, *a, **kw):       return self.send(packing.flat(*a,**kw))
