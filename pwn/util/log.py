import sys, time
from pwn import TRACE, DEBUG
from text import *
from threading import Thread

def _trace(s):
    if TRACE:
        sys.stderr.write(s)
        sys.stderr.flush()

def _debug(s):
    if DEBUG:
        sys.stderr.write(s)
        sys.stderr.flush()

_spinner = None

class _Spinner(Thread):
    def __init__(self, s, progress):
        Thread.__init__(self)
        self.status = ''
        self.progress = progress
        _trace(''.join([' ', boldblue('[ ]'), ' ', s + ': ']))

    def _update(self, color, symb, s):
        self._tty_out(''.join(['\x1b[s\x1b[2G', color('[' + symb + ']'), '\x1b[u\x1b[s', s, '\x1b[K\x1b[u']))

    def _tty_out(self, s):
        if sys.stderr.isatty() and not DEBUG:
            _trace(s)

    def run(self):
        i = 0
        spinner = '|/-\\'
        self._tty_out('\x1b[?25l')
        while True:
            if self.progress:
                self.status = self.progress()

            if isinstance(self.status, bool):
                break

            self._update(boldblue, spinner[i], self.status)
            i = (i + 1) % len(spinner)
            time.sleep(0.1)

        if self.status == False:
            self._update(boldred, '-', '')
            _trace(boldred('FAILED!') + '\n')
        else:
            self._update(boldgreen, '+', '')
            _trace(bold('Done') + '\n')
        self._tty_out('\x1b[?25h')

def _stop_spinner(status = True):
    global _spinner
    if _spinner is not None:
        _spinner.status = status
        _spinner.join()
    _spinner = None

def _start_spinner(s, progress = None):
    global _spinner
    if _spinner is not None:
        _stop_spinner()
    _spinner = _Spinner(s, progress)
    _spinner.daemon = True
    _spinner.start()

    if progress:
        _spinner.join()
        res = _spinner.status
        _spinner = None
        return res

def waitfor_done(status = True):
    _stop_spinner(status)

def waitfor(s, progress = None):
    '''The sematics of this function is, that no function is given, then
       it returns immediately and continues to spin until a call
       waitfor_done. As a convenience, the other calls in this file will
       also stop a spinner with a suitable status-code.

       If a function is given, then it blocks until the function returns
       either True or False, with True indicating success and False
       indicating a failure. The call to waitfor will also return this
       status.

       While waiting for the function to return True/False, waitfor will
       display any string-value the function returns.'''

    _start_spinner(s, progress)

def trace(s):
    _stop_spinner(True)
    _trace(s)

def debug(s):
    _stop_spinner(True)
    _debug(s)

def success(s):
    _stop_spinner(True)
    trace(''.join([' ', boldgreen('[+]'), ' ', s]))

def failure(s):
    _stop_spinner(False)
    trace(''.join([' ', boldred('[-]'), ' ', s]))

def succeeded(s):
    _stop_spinner(True)
    success(s)

def failed(s):
    _stop_spinner(False)
    failure(s)

def error(s):
    _stop_spinner(False)
    failure(s)

def warning(s):
    _stop_spinner(True)
    trace(''.join([' ', boldyellow('[!]'), ' ', s]))

def info(s):
    _stop_spinner(True)
    trace(''.join([' ', boldblue('[*]'), ' ', s]))


