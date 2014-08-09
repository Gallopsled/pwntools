from .. import log, log_levels, term
from . import tube
import serial, time, threading, sys

class serialtube(tube.tube):
    def __init__(
            self, port = '/dev/ttyUSB0', baudrate = 115200,
            convert_newlines = True,
            bytesize = 8, parity='N', stopbits=1, xonxoff = False,
            rtscts = False, dsrdtr = False,
            timeout = 'default', log_level = log_levels.INFO):
        super(serialtube, self).__init__(timeout, log_level)

        self.convert_newlines = convert_newlines
        self.conn = serial.Serial(
            port = port,
            baudrate = baudrate,
            bytesize = 8,
            parity = 'N',
            stopbits = 1,
            timeout = 0.001,
            xonxoff = False,
            rtscts = False,
            writeTimeout = 0.001,
            dsrdtr = False,
            interCharTimeout = 0.001
        )

    # Implementation of the methods required for tube
    def recv_raw(self, numb):
        if self.timeout == None:
            end = time.time() + 100000000
        else:
            end = time.time() + self.timeout

        while end > time.time():
            data = self.conn.read(numb)
            if data:
                return data
            else:
                time.sleep(0.1)

        return None

    def send_raw(self, data):
        if self.convert_newlines:
            data = data.replace('\n', '\r\n')

        while data:
            n = self.conn.write(data)
            data = data[n:]
        self.conn.flush()

    def settimeout_raw(self, timeout):
        pass

    def can_recv_raw(self, timeout):
        return self.conn.inWaiting() > 0

    def connected_raw(self, direction):
        return True

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
        log.info('Switching to interactive mode', log_level = self.log_level)

        # Save this to restore later
        debug_log_level = self.debug_log_level
        self.debug_log_level = 0

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
                    sys.stdout.write(cur)
                    sys.stdout.flush()
                except EOFError:
                    log.info('Got EOF while reading in interactive', log_level = self.log_level)
                    go[0] = False
                    break

        t = threading.Thread(target = recv_thread, args = (go,))
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
                    log.info('Got EOF while sending in interactive',
                             log_level = self.log_level)

        while t.is_alive():
            t.join(timeout = 0.1)

        # Restore
        self.debug_log_level = debug_log_level
        term.term.hide_cursor()
