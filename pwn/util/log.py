# -*- coding: utf-8 -*-

import sys, time, random
from pwn import TRACE, DEBUG
from text import *
from threading import Thread, Lock
from excepthook import addexcepthook

def _trace(s):
    if TRACE:
        sys.stderr.write(s)
        sys.stderr.flush()

def _debug(s):
    if DEBUG:
        sys.stderr.write(s)
        sys.stderr.flush()

if sys.stderr.isatty() and not DEBUG:
    _spinner = None
    _offset = 0
    _lock = Lock()

    class _Spinner(Thread):
        def __init__(self):
            Thread.__init__(self)
            self.running = True

        def run(self):
            i = 0
            spinner = random.choice([
                    ['|', '/', '-', '\\'],
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

            _trace('\x1b[?25l') # hide curser
            while True:
                _lock.acquire()
                if self.running:
                    _trace('\x1b[s\x1b[3G' + boldblue(spinner[i]) + '\x1b[u')
                    _lock.release()
                else:
                    _lock.release()
                    break
                i = (i + 1) % len(spinner)
                time.sleep(0.1)

    def _stop_spinner(marker = boldblue('[*]'), status = ''):
        global _spinner
        if _spinner is not None:
            _lock.acquire()
            _spinner.running = False
            s = []
            s.append('\x1b[?25h') # show cursor
            s.append('\x1b[2G')
            s.append(marker)
            if status:
                s.append('\x1b[%dG\x1b[0K' % _offset)
                s.append(': ')
                s.append(status)
            s.append('\n')
            _trace(''.join(s))
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
        _spinner.daemon = True
        _spinner.start()

    def trace(s):
        _stop_spinner()
        _trace(s)

    def debug(s):
        _stop_spinner()
        _debug(s)

    def waitfor(s):
        if _spinner is not None:
            raise Exception('waitfor has already been called')
        global _offset
        trace(''.join([' ', boldblue('[ ]'), ' ', s]))
        _offset = len(s) + 6
        _start_spinner()

    def status(s):
        if _spinner is None:
            raise Exception('waitfor has not been called')
        _lock.acquire()
        _trace('\x1b[%dG\x1b[0K' % _offset)
        if s:
            _trace(': ' + s)
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
