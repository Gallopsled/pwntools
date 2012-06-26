import pwn, socket, time, sys
from threading import Thread
from Queue import Queue, Empty
from subprocess import *

class Local:
    def __init__(self, cmd):
        self.debug = pwn.DEBUG
        self._q = Queue()
        self._p = Popen(cmd.split(), stdin=PIPE, stdout=PIPE, stderr=PIPE)
        def loop():
            while True:
                self._q.put(self._p.stdout.readline())
        t = Thread(target = loop)
        t.daemon = True
        t.start()

    def send(self, dat):
        self._p.stdin.write(dat)

    def recv(self):
        r = []
        while True:
            try:
                r.append(self._q.get_nowait())
            except Empty:
                break
        r = ''.join(r)
        if self.debug:
            sys.stdout.write(r)
            sys.stdout.flush()
        return r

    def close(self):
        self._p.terminate()

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
