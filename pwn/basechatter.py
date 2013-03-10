import pwn, socket, time, sys, re, errno
import errno
from pwn import log, text

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

    def __init__(self, timeout = 'default', fatal_exceptions = True):
        self.debug = pwn.DEBUG
        self.settimeout(timeout)
        self.fatal_exceptions = fatal_exceptions

    def settimeout(self, n):
        if n == 'default':
            n = 2.0
        elif n == None:
            n = 3600.0
        self.timeout = n

    def send(self, *dat):
        dat = pwn.flat(dat)
        self._send(dat)

    def sendline(self, *line):
        line = pwn.flat(line)
        self.send(line + '\n')

    def recv(self, numb = 4096):
        try:
            res = self._recv(numb)
        except socket.timeout:
            return ''
        except IOError as e:
            if e.errno == errno.EAGAIN:
                return ''
            raise
        if self.debug:
            sys.stderr.write(res)
            sys.stderr.flush()
        return res

    def recvn(self, numb):
        res = []
        n = 0
        while n < numb:
            c = self.recv(1)
            if not c:
                break
            res.append(c)
            n += 1
        return ''.join(res)

    def recvuntil(self, delim = None, **kwargs):
        if 'regex' in kwargs:
            expr = re.compile(kwargs['regex'], re.DOTALL)
            pred = lambda s: expr.match(s)
        elif 'pred' in kwargs:
            pred = kwargs['pred']
        elif delim != None:
            pred = lambda s: s.endswith(delim)
        else:
            pwn.die('recvuntil called without delim, regex or pred')

        res = ''

        while not pred(res):
            c = self.recv(1)
            if not c:
                break

            res += c
        return res

    def sendafter(self, delim, *dat):
        dat = pwn.flat(dat)
        res = self.recvuntil(delim)
        self.send(dat)
        return res

    def sendwhen(self, *dat, **kwargs):
        dat = pwn.flat(dat)
        res = self.recvuntil(**kwargs)
        self.send(dat)
        return res

    def recvline(self, lines = 1):
        res = []
        for _ in range(lines):
            res.append(self.recvuntil('\n'))
        return ''.join(res)

    def interactive(self, prompt = text.boldred('$') + ' ', clean_sock = True):
        if clean_sock:
            self.clean_sock()
        log.info('Switching to interactive mode')
        import rlcompleter
        debug = self.debug
        timeout = self.timeout
        self.debug = False
        self.settimeout(0.1)
        running = True
        def loop():
            while running:
                sys.stderr.write(self.recv(4096))
                sys.stderr.flush()
        t = pwn.Thread(target = loop)
        t.daemon = True
        t.start()
        while True:
            try:
                time.sleep(0.1)
                self.send(raw_input(prompt) + '\n')
            except (KeyboardInterrupt, EOFError):
                sys.stderr.write('Interrupted\n')
                running = False
                t.join()
                self.debug = debug
                self.settimeout(timeout)
                break

    def recvall(self):
        log.waitfor('Recieving all data')
        r = []
        l = 0
        while True:
            s = self.recv()
            if s == '': break
            r.append(s)
            l += len(s)
            log.status(pwn.size(l))
        self.close()
        return ''.join(r)

    def clean_sock(self):
        tmp_timeout = self.timeout
        self.settimeout(0.1)

        while self.recv(10000) != '':
            pass
        self.settimeout(tmp_timeout)
