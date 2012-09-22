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

if sys.stderr.isatty():
    _spinner = None

    class _Spinner(Thread):
        def __init__(self):
            Thread.__init__(self)
            self.running = True

        def run(self):
            i = 0
            spinner = '|/-\\'
            _trace('\x1b[?25l')
            while self.running:
                _trace('\x1b[3G' + boldblue(spinner[i]))
                i = (i + 1) % len(spinner)
                time.sleep(0.1)

    def _stop_spinner():
        global _spinner
        if _spinner is not None:
            _spinner.running = False
            _trace('\x1b[?25h\x1b[2K\x1b[0G')
        _spinner = None

    def _start_spinner():
        global _spinner
        if _spinner is not None:
            _stop_spinner()
        _spinner = _Spinner()
        _spinner.daemon = True
        _spinner.start()

    def trace(s):
        _stop_spinner()
        _trace(s)

    def debug(s):
        _stop_spinner()
        _debug(s)

    def waitfor(s):
        trace(''.join([' ', boldblue('[ ]'), ' ', s]))
        _start_spinner()
else:
    def trace(s):
        _trace(s)

    def debug(s):
        _debug(s)

    def waitfor(s):
        info(s + '...\n')


def success(s):
    trace(''.join([' ', boldgreen('[+]'), ' ', s]))

def failure(s):
    trace(''.join([' ', boldred('[-]'), ' ', s]))

def succeeded(s):
    success(s)

def failed(s):
    failure(s)

def error(s):
    failure(s)

def warning(s):
    trace(''.join([' ', boldyellow('[!]'), ' ', s]))

def info(s):
    trace(''.join([' ', boldblue('[*]'), ' ', s]))


