# -*- coding: utf-8 -*-

import sys, time, random, pwn
from text import *
from threading import Thread, Lock
from excepthook import addexcepthook

def _trace(s):
    if pwn.TRACE:
        sys.stderr.write(s)
        sys.stderr.flush()

def _debug(s):
    if pwn.DEBUG:
        sys.stderr.write(s)
        sys.stderr.flush()

if sys.stderr.isatty() and not pwn.DEBUG:
    _spinner = None
    _message = ''
    _status = ''
    _lock = Lock()

    class _Spinner(Thread):
        def __init__(self):
            Thread.__init__(self)
            self.running = True
            self.i = 0
            self.spinner = random.choice([
                    ['|', '/', '-', '\\'],
                    ['q', 'p', 'b', 'd'],
                    ['.', 'o', 'O', '0', '*', ' ', ' ', ' '],
                    ['▁', '▃', '▄', '▅', '▆', '▇', '█', '▇', '▆', '▅', '▄', '▃'],
                    ['┤', '┘', '┴', '└', '├', '┌', '┬', '┐'],
                    ['←', '↖', '↑', '↗', '→', '↘', '↓', '↙'],
                    ['◢', '◢', '◣', '◣', '◤', '◤', '◥', '◥'],
                    ['◐', '◓', '◑', '◒'],
                    ['▖', '▘', '▝', '▗'],
                    ['.', 'o', 'O', '°', ' ', ' ', '°', 'O', 'o', '.', ' ', ' '],
                    ['<', '<', '∧', '∧', '>', '>', 'v', 'v']
            ])

        def update(self):
            s = '\x1b[s ' + boldblue('[' + self.spinner[self.i] + ']') + ' ' + _message
            if _status and _message:
                s += ': ' + _status
            elif status:
                s += _status
            _trace(s + '\x1b[u')

        def run(self):

            _trace('\x1b[?25l') # hide curser
            while True:
                _lock.acquire()
                if self.running:
                    self.update()
                    _lock.release()
                else:
                    _lock.release()
                    break
                self.i = (self.i + 1) % len(self.spinner)
                time.sleep(0.1)

    def _stop_spinner(marker = boldblue('[*]'), status = ''):
        global _spinner, _status
        if _spinner is not None:
            _lock.acquire()
            _spinner.running = False
            _status = ''
            s = '\x1b[0K ' + marker + ' ' + _message
            if status and _message:
                s += ': ' + status
            elif status:
                s += status
            _trace(s + '\n\x1b[?25h') # show cursor
            _lock.release()
        _spinner = None

    def _hook(*args):
        global _spinner
        if _spinner is not None:
            _spinner.running = False
            _spinner = None
        _trace(' ' + boldyellow('[!]') + ' Anything is possible when your exploit smells like x86 and not a lady\n')
        _trace(' ' + boldyellow('[!]') + ' I\'m on a pwnie!\n\x1b[?25h\x1b[0m')

    addexcepthook(_hook) # reset, show cursor

    def _start_spinner():
        global _spinner
        if _spinner is not None:
            _stop_spinner()
        _spinner = _Spinner()
        _spinner.update()
        _spinner.daemon = True
        _spinner.start()

    def trace(s):
        _stop_spinner()
        _trace(s)

    def debug(s):
        _stop_spinner()
        _debug(s)

    def waitfor(s):
        global _message
        if _spinner is not None:
            raise Exception('waitfor has already been called')
        _message = s
        _start_spinner()

    def status(s):
        global _status
        if _spinner is None:
            raise Exception('waitfor has not been called')
        _lock.acquire()
        _trace('\x1b[%dG\x1b[0K\x1b[0G' % (len(_message) + len(_status) + 8))
        _status = s
        _spinner.update()
        _lock.release()

    def succeeded(s = 'Done'):
        _stop_spinner(boldgreen('[+]'), s)

    def failed(s = 'FAILED!'):
        _stop_spinner(boldred('[-]'), s)

else:
    _message = ''

    def trace(s):
        _trace(s)

    def debug(s):
        _debug(s)

    def waitfor(s):
        global _message
        _message = s
        trace(''.join([' ', boldblue('[*]'), ' ', s, '...\n']))

    def status(s):
        pass

    def succeeded(s = 'Done'):
        trace(''.join([' ', boldgreen('[+]'), ' ', _message, ': ', s, '\n']))

    def failed(s = 'FAILED!'):
        trace(''.join([' ', boldred('[-]'), ' ', _message, ': ', s, '\n']))

def success(s):
    trace(''.join([' ', boldgreen('[+]'), ' ', s, '\n']))

def failure(s):
    trace(''.join([' ', boldred('[-]'), ' ', s, '\n']))

def error(s):
    failure(s)

def warning(s):
    trace(''.join([' ', boldyellow('[!]'), ' ', s, '\n']))

def info(s):
    trace(''.join([' ', boldblue('[*]'), ' ', s, '\n']))
