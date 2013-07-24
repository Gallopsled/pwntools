import pwn

class basechatter:
    def connected(self):
        pwn.bug('This should be implemented in the sub-class')

    def close(self):
        pwn.bug('This should be implemented in the sub-class')

    def _send(self, *dat):
        pwn.bug('This should be implemented in the sub-class')

    def _recv(self, numb):
        '''The semantics of recv is that it should return up to numb-bytes as soon as any bytes are available.
        If no bytes are available within self.timeout seconds, it should return the empty string.

        In the event that further communication is impossible (such as a closed socket) a suitable exception should be raised.
        '''
        pwn.bug('This should be implemented in the sub-class')

    def fileno(self):
        pwn.bug('This should be implemented in the sub-class')

    def can_recv(self, timeout = 0):
        import select
        return select.select([self], [], [], timeout) == ([self], [], [])

    def __init__(self, timeout = 'default', silent = False):
        self.debug = pwn.DEBUG
        self.silent = silent
        self.settimeout(timeout)

    def settimeout(self, n):
        '''Sets the timeout for the socket.'''
        if n == 'default':
            n = 2.0
        elif n == None:
            n = 3600.0
        self.timeout = n

    def send(self, *dat):
        '''Sends data to the socket.'''
        dat = pwn.flat(dat)
        self._send(dat)

    def sendline(self, *line):
        '''Sends data to the socket appended with a newline.'''
        line = pwn.flat(line)
        self.send(line + '\n')

    def recv(self, numb = 4096):
        '''Receives up to numb bytes of data from the socket. It returns as soon as data is available.'''
        import socket, sys
        try:
            res = self._recv(numb)
        except socket.timeout:
            return ''
        except IOError as e:
            import errno
            if e.errno == errno.EAGAIN:
                return ''
            raise
        if self.debug:
            sys.stderr.write(res)
            sys.stderr.flush()
        return res

    def recvn(self, numb):
        '''Receives exactly numb bytes of data from the socket, unless the socket is closed in which case it returns.'''
        res = []
        n = 0
        while n < numb:
            c = self.recv(1)
            if not c:
                break
            res.append(c)
            n += 1
        return ''.join(res)

    def recvuntil(self, delim = None, regex = None, pred = None):
        '''Receives data from the socket until  numb bytes of data from the socket, unless the socket is closed in which case it returns.'''
        if regex != None:
            import re
            expr = re.compile('regex', re.DOTALL)
            pred = lambda s: expr.match(s)
        elif delim != None:
            pred = lambda s: s.endswith(delim)
        elif pred == None:
            pwn.die('recvuntil called without delim, regex or pred')

        res = ''

        while not pred(res):
            c = self.recv(1)
            if not c:
                break

            res += c
        return res

    def sendafter(self, delim, *dat):
        """ Wait for delim, then send *dat"""
        dat = pwn.flat(dat)
        res = self.recvuntil(delim)
        self.send(dat)
        return res

    def sendlineafter(self, delim, *dat):
        ''' Like sendafter, but appends a newline'''
        dat = pwn.flat(dat)
        res = self.recvuntil(delim)
        self.send(dat + '\n')
        return res

    def sendthen(self, delim, *dat):
        """ Send *dat, then wait for delim"""
        dat = pwn.flat(dat)
        self.send(dat)
        res = self.recvuntil(delim)
        return res

    def sendlinethen(self, delim, *dat):
        ''' Like sendthen, but appends a newline'''
        dat = pwn.flat(dat)
        self.send(dat + '\n')
        res = self.recvuntil(delim)
        return res

    def recvline(self, lines = 1):
        ''' Receives one or more lines from the socket. '''
        res = []
        for _ in range(lines):
            res.append(self.recvuntil('\n'))
        return ''.join(res)

    def interactive(self, prompt = pwn.text.boldred('$') + ' ', flush_timeout = None):
        ''' 'Connects' a socket to stdin/stdout. Very effective if combined with the findpeersh shellcode.
        
        It can optionally have a prompt, which it tries to print out when output has not been seen for a while. '''
        if not self.silent:
            pwn.log.info('Switching to interactive mode')
        import readline, sys
        debug = self.debug
        timeout = self.timeout
        self.debug = False
        self.settimeout(0.1)

        def write(s):
            sys.stdout.write(s)
        def save():
            write('\x1b[s')
        def restore():
            write('\x1b[u')
        def reprompt():
            write(prompt)
            write(readline.get_line_buffer())
            sys.stdout.flush()

        running = [True] # the old by-ref trick
        def loop():
            import time
            buf = ''
            buft = time.time()
            newline = True
            while running[0]:
                if not self.can_recv(0.1):
                    continue
                try:
                    data = self.recv()
                except EOFError:
                    write('\nConnection closed\n')
                    running[0] = False
                    break
                now = time.time()
                lines = data.split('\n')
                if len(lines) == 1:
                    buf += lines[0]
                    if buf == '':
                        continue
                    # 1. if the readline buffer is empty there is no position to
                    #    remember
                    # 2. if we are not just after a newline we already fucked
                    #    the readline buffer up
                    # 3. if the timeout is reached, screw it we'll fuck the
                    #    readline buffer up in exchange for some output
                    if readline.get_line_buffer() == '' or \
                      not newline or \
                      (flush_timeout <> None and now - buft >= flush_timeout):
                        if newline:
                            write('\x1b[1G')
                        else:
                            restore()
                        write(buf)
                        save()
                        reprompt()
                        buf = ''
                        buft = now
                        newline = False
                else:
                    lines[0] = buf + lines[0]
                    if newline:
                        save()
                        write('\x1b[1G\x1b[J')
                    else:
                        restore()
                        write('\x1b[J')
                    for line in lines[:-1]:
                        write(line + '\n')
                    buf = lines[-1]
                    buft = now
                    reprompt()
                    if newline:
                        restore()
                    newline = True

        save()
        t = pwn.Thread(target = loop)
        t.daemon = True
        t.start()
        try:
            while True:
                self.send(raw_input(prompt) + '\n')
                if not running[0]:
                    t.join()
                    break
        except (KeyboardInterrupt, EOFError):
            if running[0]:
                running[0] = False
                t.join()
                write('\nInterrupted\n')
            else:
                t.join()
        except IOError:
            running[0] = False
            t.join()
            write('Connection closed\n')
        self.debug = debug
        self.settimeout(timeout)

    def recvall(self):
        ''' Receives data until a socket is closed. '''
        if not self.silent:
            pwn.log.waitfor('Recieving all data')
        r = []
        l = 0
        while True:
            s = self.recv()
            if s == '': break
            r.append(s)
            l += len(s)
            if not self.silent:
                pwn.log.status(pwn.size(l))
        if not self.silent:
            pwn.log.succeeded()
        return ''.join(r)

    def clean(self):
        ''' Removes all the buffered data from a socket. '''
        tmp_timeout = self.timeout
        self.settimeout(0.1)

        while self.recv(10000) != '':
            pass
        self.settimeout(tmp_timeout)

    def attach_gdb(self, execute = None):
        ''' Tries to find the program in the other end of a socket (if it is a local program).
        
        It then creates a new gdb session in a new terminal windows, which is then connected to the program in the other end.'''
        pwn.attach_gdb(self, execute)

