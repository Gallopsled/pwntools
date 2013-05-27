# -*- coding: utf-8 -*-

import sys, time, random, pwn
from pwn.internal.excepthook import addexcepthook
import pwn.text as text
import threading

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
    _lock = threading.Lock()

    class _Spinner(threading.Thread):
        def __init__(self):
            threading.Thread.__init__(self)
            self.running = True
            self.i = 0
            self.numlines = 0
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

        def format(self, marker, status):
            s = '\x1b[J ' + marker + ' ' + _message
            if status and _message:
                s += ': '
            lines = status.split('\n')
            lines += [''] * (self.numlines - len(lines) - 1)
            if len(lines) > 1:
                if lines[0] == '':
                    lines = lines[1:]
                pref = '\n       '
                s += pref
                s += pref.join(lines)
                self.numlines = len(lines) + 1
            else:
                s += status
            return s

        def update(self, only_spin = False):
            _lock.acquire()
            marker = text.boldblue('[' + self.spinner[self.i] + ']')
            if only_spin:
                _trace('\x1b[s ' + marker + '\x1b[u')
            else:
                s = self.format(marker, _status)
                if self.numlines <= 1:
                    s += '\x1b[G'
                else:
                    s += '\x1b[%dF' % (self.numlines - 1)
                _trace(s)
            _lock.release()

        def finish(self, marker, status):
            if not status:
                _trace(' ' + marker + '\x1b[%dE\n' % self.numlines)
            elif '\n' not in status:
                s = '\x1b[K ' + marker + ' ' + _message + ': ' + status
                if self.numlines > 1:
                    s += '\x1b[%dE' % (self.numlines - 1)
                s += '\n'
                _trace(s)
            else:
                _trace(self.format(marker, status) + '\n')
            _trace('\x1b[?25h')

        def run(self):
            global _marker
            _trace('\x1b[?25l') # hide curser
            while True:
                if self.running:
                    self.update(True)
                else:
                    break
                self.i = (self.i + 1) % len(self.spinner)
                time.sleep(0.1)

    def _stop_spinner(marker = text.boldblue('[*]'), status = ''):
        global _spinner, _status

        if _spinner is None:
            return

        _spinner.running = False
        _spinner.join()
        _spinner.finish(marker, status)
        _spinner = None

    def _hook(*args):
        global _spinner
        _stop_spinner('')
        _trace(' ' + text.boldyellow('[!]') + ' Anything is possible when your exploit smells like x86 and not a lady\n')
        _trace(' ' + text.boldyellow('[!]') + ' I\'m on a pwnie!\n\x1b[?25h\x1b[0m')

    addexcepthook(_hook) # reset, show cursor

    def _start_spinner():
        global _spinner
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
        _status = s
        _lock.release()
        _spinner.update()

    def status_append(s):
        global _status
        if _spinner is None:
            raise Exception('waitfor has not been called')
        _lock.acquire()
        _status += s
        _lock.release()
        _spinner.update()

    def succeeded(s = 'Done'):
        _stop_spinner(text.boldgreen('[+]'), s)

    def failed(s = 'FAILED!'):
        _stop_spinner(text.boldred('[-]'), s)

else:
    _message = ''

    def trace(s):
        _trace(s)

    def debug(s):
        _debug(s)

    def waitfor(s):
        global _message
        _message = s
        trace(''.join([' ', text.boldblue('[*]'), ' ', s, '...\n']))

    def status(s):
        pass

    def status_append(s):
        pass

    def succeeded(s = 'Done'):
        trace(''.join([' ', text.boldgreen('[+]'), ' ', _message, ': ', s, '\n']))

    def failed(s = 'FAILED!'):
        trace(''.join([' ', text.boldred('[-]'), ' ', _message, ': ', s, '\n']))

def success(s):
    trace(''.join([' ', text.boldgreen('[+]'), ' ', s, '\n']))

def failure(s):
    trace(''.join([' ', text.boldred('[-]'), ' ', s, '\n']))

def error(s):
    failure(s)

def warning(s):
    trace(''.join([' ', text.boldyellow('[!]'), ' ', s, '\n']))

def info(s):
    trace(''.join([' ', text.boldblue('[*]'), ' ', s, '\n']))

def die(s = None, e = None, exit_code = -1):
    """Exits the program with an error string and optionally prints an exception."""
    if s:
        failure('FATAL: ' + s)
    if e:
        failure('The exception was:')
        trace(str(e) + '\n')
    sys.exit(exit_code)

def bug(s = None, e = None, exit_code = -1):
    """Called when the program enters a state that should not be possible."""
    if s:
        failure('BUG (this should not happen): ' + s)
    if e:
        failure('The exception was:')
        trace(str(e) + '\n')
    sys.exit(exit_code)
