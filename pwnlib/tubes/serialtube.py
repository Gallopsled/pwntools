from __future__ import absolute_import
from __future__ import division

import glob
import platform
import sys
import time

import serial

from pwnlib.log import getLogger
from pwnlib.tubes import tube

log = getLogger(__name__)

class serialtube(tube.tube):
    def __init__(
            self, port = None, baudrate = 115200,
            convert_newlines = True,
            bytesize = 8, parity='N', stopbits=1, xonxoff = False,
            rtscts = False, dsrdtr = False, *a, **kw):
        """
        Initializes a serial tube

        If some parameter is invalid and triggers a serial.SerialException
        during initialization, the function propagates this error with a call 
        to self.exception().
        """
        super(serialtube, self).__init__(*a, **kw)

        if port is None:
            if platform.system() == 'Darwin':
                port = glob.glob('/dev/tty.usbserial*')[0]
            else:
                port = '/dev/ttyUSB0'

        self.convert_newlines = convert_newlines
        # serial.Serial might throw an exception, which must be handled
        # and propagated accordingly using self.exception
        try:
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
        except serial.SerialException:
            # self.conn is set to None to avoid an AttributeError when
            # initialization fails, but the program still tries closing
            # the serial tube anyway
            self.conn = None
            self.exception("Could not open a serial tube on port %s", port)

    # Implementation of the methods required for tube
    def recv_raw(self, numb):
        """
        Method that receives `numb` bytes from a serial tube

        Arguments: 
            numb(int): number of bytes to read from the connection
        
        Returns:
            data received from the connection or None
        """
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
            data = data.replace(b'\n', b'\r\n')

        while data:
            n = self.conn.write(data)
            data = data[n:]
        self.conn.flush()

    def settimeout_raw(self, timeout):
        """
        Method to set the timeout of a serial tube.

        Currently unimplemented
        """
        pass

    def can_recv_raw(self, timeout):
        """
        Method to indicate if a serial tube is waiting
        and can receive data. 

        Arguments:
            timeout: a duration in number of seconds
        
        Returns:
            A boolean to indicate if the current serial tube can receive
            data
        """
        with self.countdown(timeout):
            while self.conn and self.countdown_active():
                if self.conn.inWaiting():
                    return True
                time.sleep(min(self.timeout, 0.1))
        return False

    def connected_raw(self, direction):
        return self.conn is not None

    def close(self):
        """
        Method that attempts to close a serial tube if it has an open
        connection
        """
        if self.conn:
            self.conn.close()
            self.conn = None

    def fileno(self):
        """
        Method that returns the fileno of the serial connection

        Returns:
            An integer representing the fileno
        """
        if not self.connected():
            self.error("A closed serialtube does not have a file number")

        return self.conn.fileno()

    def shutdown_raw(self, direction):
        self.close()
