import pwn, socket, time, sys
from threading import Thread

class Remote:
    def __init__(self, host, port):
        self.target = (host, port)
        self.sock = None
        self.debug = pwn.DEBUG
        self._buf = []
        self.connect()

    def connect(self):
        self.close()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect(self.target)

    def close(self):
        if self.sock:
            self.sock.close()
            self.sock = None

    def send(self, dat):
        self.sock.send(dat)

    def recv(self, numb = 1024):
        if len(self._buf) > 0:
            res = ''.join(self._buf)
            self._buf = []
        else:
            res = self.sock.recv(numb)
        if self.debug:
            sys.stdout.write(res)
            sys.stdout.flush()
        return res

    def recvn(self, numb):
        res = []
        c = 0
        while c < numb:
            x = self.recv()
            c += len(x)
            res.append(x)
        res = ''.join(res)
        self._buf = [res[:numb - c]]
        return res[numb:]

    def recvline(self):
        res = []
        while True:
            x = self.recv()
            i = x.find('\n')
            if i >= 0:
                res.append(x[i:])
                self._buf = [x[:i + 1]]
                break
            res.append(x)
        return ''.join(res)

    def recv_and_close(self):
        res = []
        while True:
            x = self.recv()
            if x:
                res.append(x)
                continue
            break
        return ''.join(res)

    def interactive(self, prompt = '> '):
        self.debug = True
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
                break
