import glob
import platform
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
            self, port = None, baudrate = 115200,
            convert_newlines = True,
            bytesize = 8, parity='N', stopbits=1, xonxoff = False,
            rtscts = False, dsrdtr = False, *a, **kw):
        super(serialtube, self).__init__(*a, **kw)

        if port is None:
            if platform.system() == 'Darwin':
                port = glob.glob('/dev/tty.usbserial*')[0]
            else:
                port = '/dev/ttyUSB0'

        self.convert_newlines = convert_newlines
        self.conn = serial.Serial(
            port = port,
            baudrate = baudrate,
            bytesize = bytesize,
            parity = parity,
            stopbits = stopbits,
            timeout = 0,
            xonxoff = xonxoff,
            rtscts = rtscts,
            writeTimeout = None,
            dsrdtr = dsrdtr,
            interCharTimeout = 0
        )

    # Implementation of the methods required for tube
    def recv_raw(self, numb):
        if not self.conn:
            raise EOFError

        with self.countdown():
            while self.conn and self.countdown_active():
                data = self.conn.read(numb)

                if data:
                    return data

                time.sleep(min(self.timeout, 0.1))

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
        with self.countdown(timeout):
            while self.conn and self.countdown_active():
                if self.conn.inWaiting():
                    return True
                time.sleep(min(self.timeout, 0.1))
        return False

    def connected_raw(self, direction):
        return self.conn != None

    def close(self):
        if self.conn:
            self.conn.close()
            self.conn = None

    def fileno(self):
        if not self.connected():
            self.error("A closed serialtube does not have a file number")

        return self.conn.fileno()

    def shutdown_raw(self, direction):
        self.close()
