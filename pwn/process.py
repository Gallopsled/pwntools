import pwn, sys, time
from pwn import log, text
from subprocess import Popen, PIPE
import fcntl, os
from basechatter import basechatter
import time

class process(basechatter):
    def __init__(self, cmd, *args, **kwargs):
        timeout = kwargs.get('timeout', 'default')
        env = kwargs.get('env', {})

        basechatter.__init__(self, timeout)
        self.proc = None

        self.start(cmd, args, env)

    def start(self, cmd, args, env):
        if self.connected():
            log.warning('Program "%s" already started' % cmd)
            return
        log.waitfor('Starting program "%s"' % cmd)

        self.proc = Popen(
                tuple(cmd.split()) + args,
                stdin=PIPE, stdout=PIPE, stderr=PIPE,
                env = env,
                bufsize = 0)
        fd = self.proc.stdout.fileno()
        fl = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
        log.succeeded()

    def connected(self):
        return self.proc != None

    def close(self):
        if self.proc:
            self.proc.kill()
            self.proc = None

    def _send(self, dat):
        self.proc.stdin.write(dat)
        self.proc.stdin.flush()

    def _recv(self, numb):
        end_time = time.time() + self.timeout

        while True:
            r = ''
            try:
                r = self.proc.stdout.read(numb)
            except IOError as e:
                if e.errno != 11:
                    raise

            if r or time.time() > end_time:
                break
            time.sleep(0.0001)
        return r
