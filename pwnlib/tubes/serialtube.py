import sys
import time

import serial

from . import tube
from .. import context
from .. import term
from ..log import getLogger

log = getLogger(__name__)

class serialtube(tube.tube):
    def __init__(
            self, port = '/dev/ttyUSB0', baudrate = 115200,
            convert_newlines = True,
            bytesize = 8, parity='N', stopbits=1, xonxoff = False,
            rtscts = False, dsrdtr = False,
            timeout = 'default'):
        super(serialtube, self).__init__(timeout)

        self.convert_newlines = convert_newlines
        self.conn = serial.Serial(
            port = port,
            baudrate = baudrate,
            bytesize = 8,
            parity = 'N',
            stopbits = 1,
            timeout = 0,
            xonxoff = False,
            rtscts = False,
            writeTimeout = None,
            dsrdtr = False,
            interCharTimeout = 0
        )

    # Implementation of the methods required for tube
    def recv_raw(self, numb):
        if not self.conn:
            raise EOFError

        if self.timeout == None:
            end = float('inf')
        else:
            end = time.time() + self.timeout

        while True:
            data = self.conn.read(numb)
            if data:
                return data

            delta = end - time.time()
            if delta <= 0:
                break
            else:
                time.sleep(min(delta, 0.1))

        return None

    def send_raw(self, data):
        if not self.conn:
            raise EOFError

        if self.convert_newlines:
            data = data.replace('\n', '\r\n')

        while data:
            n = self.conn.write(data)
            data = data[n:]
        self.conn.flush()

    def settimeout_raw(self, timeout):
        pass

    def can_recv_raw(self, timeout):
        end = time.time()
        while time.time() < end:
            if self.conn.inWaiting():
                return True
        return False

    def connected_raw(self, direction):
        return self.conn != None

    def close(self):
        if self.conn:
            self.conn.close()
            self.conn = None

    def fileno(self):
        if not self.connected():
            log.error("A stopped program does not have a file number")

        return self.conn.fileno()

    def shutdown_raw(self, direction):
        self.close()

    def interactive(self, prompt = term.text.bold_red('$') + ' '):
        log.info('Switching to interactive mode')

        # We would like a cursor, please!
        term.term.show_cursor()

        go = [True]
        def recv_thread(go):
            while go[0]:
                try:
                    cur = self.recv(timeout = 0.05)
                    if cur == None:
                        continue
                    elif cur == '\a':
                        # Ugly hack until term unstands bell characters
                        continue
                    sys.stderr.write(cur)
                    sys.stderr.flush()
                except EOFError:
                    log.info('Got EOF while reading in interactive')
                    go[0] = False
                    break

        t = context.Thread(target = recv_thread, args = (go,))
        t.daemon = True
        t.start()

        while go[0]:
            if term.term_mode:
                try:
                    data = term.key.getraw(0.1)
                except IOError:
                    if go[0]:
                        raise
            else:
                data = sys.stdin.read(1)
                if not data:
                    go[0] = False

            if data:
                try:
                    self.send(''.join(chr(c) for c in data))
                except EOFError:
                    go[0] = False
                    log.info('Got EOF while sending in interactive')

        while t.is_alive():
            t.join(timeout = 0.1)

        # Restore
        term.term.hide_cursor()
