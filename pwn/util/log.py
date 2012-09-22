import sys, time
from pwn import TRACE, DEBUG
from text import *
from threading import Thread

__spinner = None

def __start_spinner():
    global __spinner
    __spinner = __Spinner()
    __spinner.daemon = True
    __spinner.start()

def __stop_spinner():
    if __spinner is not None:
        __spinner.running = False
        trace('\x1b[?25h\x1b[2K\x1b[0G')

def trace(s):
    if TRACE:
        __stop_spinner()
        sys.stderr.write(s)
        sys.stderr.flush()

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

def debug(s):
    if DEBUG:
        __stop_spinner()
        sys.stderr.write(s)
        sys.stderr.flush()


if sys.stderr.isatty():
    class __Spinner(Thread):
        def __init__(self):
            Thread.__init__(self)
            self.running = True

        def run(self):
            i = 0
            spinner = '|/-\\'
            trace('\x1b[?25l')
            while self.running:
                trace('\x1b[3G' + boldblue(spinner[i]))
                i = (i + 1) % len(spinner)
                time.sleep(0.1)

    def waitfor(s):
        trace(''.join([' ', boldblue('[ ]'), ' ', s]))
        __start_spinner()
else:
    def waitfor(s):
        info(s + '...\n')
