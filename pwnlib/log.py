__all__ = ['trace', 'debug', 'info', 'warning', 'failure', 'success',
           'indented', 'output', 'error', 'bug', 'die', 'waitfor', 'status',
           'done_success', 'done_failure', 'DEBUG', 'INFO', 'ERROR',
           'SILENT',
           ]

import threading, sys, time
import term
import term.text as text
import context

# log-levels
DEBUG  = 10  # trace, debug
INFO   = 20  # info, (warning,) failure, success, indented, output, waitfor,
             # status, done_success, done_failure
ERROR  = 30  # error, stub, bug, fatal, die
SILENT = 100 # <nothing>


last_was_nl = True
def put(s = '', frozen = True, float = False, priority = 10, indent = 0):
    global last_was_nl
    if term.initialized:
        return term.output(str(s), frozen = frozen, float = float,
                           priority = priority, indent = indent)
    else:
        s = str(s)
        if not s:
            return _dummy_handle
        if last_was_nl:
            sys.stdout.write(' ' * indent)
            last_was_nl = False
        if s[-1] == '\n':
            last_was_nl = True
        if indent:
            s = s[:-1].replace('\n', '\n' + ' ' * indent) + s[-1]
        sys.stdout.write(s)
        return _dummy_handle

def flush():
    if not term.initialized:
        sys.stdout.flush()

# these functions are the same in all modes
def trace(s = ''):
    if context.log_level <= INFO:
        return put(s, frozen, float, priority, indent)
    else:
        return _dummy_handle

def anotate(a, s, l, frozen = True, float = False, priority = 10, indent = 0):
    if context.log_level <= l:
        put('[%s] ' % a, frozen, float, priority, indent)
        h = put(s, frozen, float, priority, indent + 4)
        put('\n', frozen, float, priority)
        return h
    else:
        return dummy_handle

def debug(s = '', frozen = True, float = False, priority = 10, indent = 0):
    return anotate(text.bold_red('DEBUG'), s, DEBUG,
                   frozen, float, priority, indent)

def info(s = '', frozen = True, float = False, priority = 10, indent = 0):
    return anotate(text.bold_blue('*'), s, INFO,
                   frozen, float, priority, indent)

def warning(s = '', frozen = True, float = False, priority = 10, indent = 0):
    if term.initialized:
        return anotate(text.bold_yello('!'), s, INFO,
                       frozen, float, priority, indent)
    else:
        import warnings
        warnings.warn(s, stacklevel = 2)

def failure(s = '', frozen = True, float = False, priority = 10, indent = 0):
    return anotate(text.bold_red('-'), s, INFO,
                   frozen, float, priority, indent)

def success(s = '', frozen = True, float = False, priority = 10, indent = 0):
    return anotate(text.bold_green('+'), s, INFO,
                   frozen, float, priority, indent)

def indented(s = '', frozen = True, float = False, priority = 10, indent = 0):
    if context.log_level <= INFO:
        h = put(s, frozen, float, priority, indent + 4)
        put('\n', frozen, float, priority)
        return h
    else:
        return _dummy_handle

def output(s = '', frozen = True, float = False, priority = 10, indent = 0):
    if context.log_level <= INFO:
        return put(s, frozen, float, priority, indent)
    else:
        return _dummy_handle

def error(s = '', exit_code = -1):
    if term.initialized:
        anotate(text.on_red('ERROR'), s, ERROR)
        if context.log_level <= INFO and sys.exc_type not in [None, KeyboardInterrupt]:
            put('The exception was:\n')
            import traceback
            traceback.print_exc()
        sys.exit(exit_code)
    else:
        import exception
        if sys.exc_type not in [None, KeyboardInterrupt]:
            reason = sys.exc_info()
        else:
            reason = None
        raise exception.PwnlibException(s, reason, exit_code)

def die(s):
    error(s)

def fatal(s = '', exit_code = -1):
    anotate(text.on_red('FATAL'), s, ERROR)
    if context.log_level <= ERROR and sys.exc_type not in [None, KeyboardInterrupt]:
        put('The exception was:\n')
        import traceback
        traceback.print_exc()
    sys.exit(exit_code)

def bug(s = '', exit_code = -1):
    anotate(text.on_red('BUG (this should not happen)'), s, ERROR)
    if context.log_level <= ERROR and sys.exc_type not in [None, KeyboardInterrupt]:
        put('The exception was:\n')
        import traceback
        traceback.print_exc()
    sys.exit(exit_code)

def stub(s = '', exit_code = -1):
    if context.log_level <= ERROR:
        import traceback
        filename, lineno, fname, _line = \
            traceback.extract_stack(limit = 2)[0]
        put('Unimplemented function: %s in file "%s", line %d\n' %
            (fname, filename, lineno))
        if s:
            put('%s\n' % s)
    sys.exit(exit_code)

class _Handle(object):
    pass

class _DummyHandle(_Handle):
    def update(self, _s):
        pass
    def freeze(self):
        pass
    def delete(self):
        pass
_dummy_handle = _DummyHandle()

class _SimpleHandle(_Handle):
    def __init__(self, msg, _spinner):
        info('%s...' % msg)
        self.msg = msg
    def status(self, _):
        pass
    def success(self, s = 'OK'):
        success('%s: %s' % (self.msg, s))
    def failure(self, s = 'FAILED!'):
        failure('%s: %s' % (self.msg, s))

class _Spinner(threading.Thread):
    def __init__(self, spinner):
        threading.Thread.__init__(self)
        self.spinner = spinner
        self.idx = 0
        self.daemon = True
        import sys as _sys
        self.sys = _sys
        self.handle = term.output()
        self.lock = threading.Lock()
        self.start()

    def run(self):
        self.running = True
        while True:
            # interpreter shutdown
            if not self.sys:
                break
            with self.lock:
                if self.running:
                    self.handle.update(
                        text.bold_blue(self.spinner[self.idx])
                        )
            self.idx = (self.idx + 1) % len(self.spinner)
            time.sleep(0.1)

    def stop(self, s):
        self.running = False
        with self.lock:
            self.handle.update(s)
            self.handle.freeze()

class _TermHandle(_Handle):
    def __init__(self, msg, spinner):
        self.hasmsg = msg <> ''
        put('[')
        if spinner is None:
            import random, term.spinners as spinners
            spinner = random.choice(spinners.spinners)
        self.spinner = _Spinner(spinner)
        put('] %s' % msg)
        self.stat = term.output()
        put('\n')
    def status(self, s):
        if self.hasmsg and s:
            s = ': ' + s
        self.stat.update(s)
    def success(self, s = 'OK'):
        if self.hasmsg and s:
            s = ': ' + s
        self.spinner.stop(text.bold_green('+'))
        self.stat.update(s)
        self.stat.freeze()
    def failure(self, s = 'FAILED!'):
        if self.hasmsg and s:
            s = ': ' + s
        self.spinner.stop(text.bold_red('-'))
        self.stat.update(s)
        self.stat.freeze()

handle_stack = []
def waitfor(msg, status = '', spinner = None):
    if term.initialized:
        h = _TermHandle(msg, spinner)
    else:
        h = _SimpleHandle(msg, spinner)
    if status:
        h.status(status)
    handle_stack.append(h)
    return h

def status(h, s = ''):
    if isinstance(h, Handle):
        h.update(s)
    elif handle_stack:
        s = h
        h = handle_stack.pop()
        h.success(s)
    else:
        error('Not waiting for anything')

def done_success(h = 'Done', s = ''):
    if isinstance(h, _Handle):
        h.success(s)
    elif handle_stack:
        s = h
        h = handle_stack.pop()
        h.success(s)
    else:
        error('Not waiting for anything')

def done_failure(h = 'FAILED!', s = ''):
    if isinstance(h, _Handle):
        h.failure(s)
    elif handle_stack:
        s = h
        h = handle_stack.pop()
        h.failure(s)
    else:
        error('Not waiting for anything')
