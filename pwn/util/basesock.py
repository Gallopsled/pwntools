import pwn, socket, time, sys
from consts import *
from threading import Thread

class basesock:
    def settimeout(self, n):
        self.timeout = n
        self.sock.settimeout(n)

    def setblocking(self, b):
        self.sock.setblocking(b)

    def close(self):
        if self.sock:
            self.sock.close()
            self.sock = None
            pwn.trace(' [+] Closed connection to %s on port %d\n' % self.target)

    def send(self, dat):
        if self.checked:
            try:
                return self.sock.send(dat)
            except socket.error, e:
                if e.errno == 32:
                    pwn.trace(' [-] Broken pipe\n')
                    exit(PWN_UNAVAILABLE)
                else:
                    raise
        else:
            return self.sock.send(dat)

    def recv(self, numb = 1024):
        if self.checked:
            try:
                res = self.sock.recv(numb)
            except socket.timeout:
                pwn.trace(' [-] Connection timed out\n')
                exit(PWN_UNAVAILABLE)
        else:
            res = self.sock.recv(numb)
        if self.debug:
            sys.stdout.write(res)
            sys.stdout.flush()
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

    def recvuntil(self, delim):
        res = self.recvn(len(delim))

        while not res.endswith(delim):
            c = self.recv(1)
            if not c:
                break

            res += c
        return res

    def recvline(self, lines = 1):
        res = []
        for _ in range(lines):
            res.append(self.recvuntil('\n'))
        return ''.join(res)

    def interactive(self, prompt = '> '):
        pwn.trace(' [+] Switching to interactive mode\n')
        debug = self.debug
        timeout = self.timeout
        self.debug = True
        self.settimeout(None)
        def loop():
            while True:
                self.recv()
        t = Thread(target = loop)
        t.daemon = True
        t.start()
        while True:
            try:
                time.sleep(0.1)
                self.send(raw_input(prompt) + '\n')
            except KeyboardInterrupt:
                self.debug = debug
                self.settimeout(timeout)
                break

    def recvall(self):
        r = []
        while True:
            s = self.recv()
            if s == '': break
            r.append(s)
        self.close()
        return ''.join(r)
