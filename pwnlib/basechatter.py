import sys
import threading

class ChatterException(Exception):
    pass

class basechatter:
    def connected(self):
        raise ChatterException("connected is not implemented in subclass")

    def recv(self, size):
        raise ChatterException("recv is not implemented in subclass")

    def send(self, data):
        raise ChatterException("send is not implemented in subclass")

    def fileno(self):
        raise ChatterException("fileno is not implemented in subclass")

    def sendline(self, line):
        self.send(line+"\n")

    def recvn(self, n):
        data = ""
        while len(data) != n:
            tmp = self.recv(n-len(data))
            if tmp == "":
                break
            data += tmp
        return data

    def recvuntil(self, delim = None, regex = None, pred = None):
        if regex != None:
            import re
            expr = re.compile(regex, re.DOTALL)
            pred = lambda s: expr.match(s)
        if delim != None:
            pred = lambda s:s.endswith(delim)
        if pred == None:
            raise ChatterException("recvuntil called without delim, regex or pred")

        data = ""

        while not pred(data):
            c = self.recv(1)
            if c == "":
                break
            data += c

        return data

    def interactive(self, prompt = "$ "):
        self.interactive_running = True
        conn_th = threading.Thread(target = self._interactive_thread_io)
        conn_th.daemon = True
        conn_th.start()
        while self.interactive_running:
            try:
                line = sys.stdin.readline()
            except KeyboardInterrupt:
                self.interactive_running = False
            self.send(line)


    def _interactive_thread_io(self):
        while self.interactive_running:
            c = self.recv(1)
            if c == "":
                sys.stdout.write("Connection closed")
                self.interactive_running = False
            sys.stdout.write(c)
            sys.stdout.flush()
