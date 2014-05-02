# The behavoir of this module depends on the context:
#
#                       .-- isatty? --.
#                      /               \
# .---------.---------.--------.--------.--------.----------.-------.------.
# | libmode | hasrepl | stdout | stderr | fancy* | loglevel | color | exc* |
# |---------+---------+--------+--------+--------+----------+-------+------|
# |     yes |     N/A |    N/A |    yes |     no |    ERROR |   yes |  yes |
# |     yes |     N/A |    N/A |     no |     no |    ERROR |    no |  yes |
# |      no |     yes |    N/A |    yes |     no |     INFO |   yes |   no |
# |      no |     yes |    N/A |     no |     no |     INFO |    no |   no |
# |      no |      no |    yes |    N/A |    yes |     INFO |   yes |   no |
# |      no |      no |    N/A |    yes |    yes |     INFO |   yes |   no |
# '---------'---------'--------'--------'--------'----------'-------'------'
#
# fancy*:
#   In this mode log functions at or below level INFO react to the same
#   arguments as `term.output'.  In particular a handle is returned which can be
#   used to update the text at a later point.  The handle returned from
#   `waitfor' can also be used to update the status text.
#
# exc*:
#   In this mode the `error' function will not generate any output, but rather
#   raise an exception of type `PwnlibException'.  If `sys.exc_type' is set then
#   the exceptions `reason' will be set to the last raised exception.
#   The `warning' function will signal warnings using the `warnings' module.

__all__ = ['trace', 'debug', 'info', 'warning', 'failure', 'success',
           'indented', 'output', 'error', 'bug', 'die', 'waitfor', 'status',
           'done_success', 'done_failure', 'loglevel', 'DEBUG', 'INFO', 'ERROR',
           'SILENT',
           ]

import text, threading, sys
import pwn2 as __pwn__

# log-levels
DEBUG  = 10  # trace, debug
INFO   = 20  # info, (warning,) failure, success, indented, output, waitfor,
             # status, done_success, done_failure
ERROR  = 30  # error, stub, bug, fatal, die
SILENT = 100 # <nothing>

# per-thread log-level
levels = {}
default_level = ERROR if __pwn__.__libmode__ else INFO

def set_level (level):
    tid = threading.current_thread().ident
    levels[tid] = level

def get_level ():
    tid = threading.current_thread().ident
    return levels.get(tid, default_level)

def has_level (level):
    return get_level() <= level

class loglevel:
    def __init__ (self, new_level):
        self.old_level = get_level()
        self.new_level = new_level
    def __enter__ (self):
        set_level(self.new_level)
    def __exit__ (self, *args):
        set_level(self.old_level)

class DummyHandle:
    def update (self, _s):
        pass
    def freeze (self):
        pass
    def delete (self):
        pass
dummy_handle = DummyHandle()

if __pwn__.__hasterm__:
    from ..nonlib import term
    OutputHandle = term.Handle
    def put (s = '', frozen = True, float = False, priority = 10, indent = 0):
        return term.output(str(s), frozen = frozen, float = float,
                           priority = priority, indent = indent)

    def flush ():
        pass

else:
    def put (s = '', frozen = None, float = None, priority = None, indent = 0):
        sys.stderr.write(' ' * indent + s)
        return dummy_handle

    def flush ():
        sys.stderr.flush()

# these functions are the same in all modes
def trace (s = ''):
    if has_level(INFO):
        return put(s, frozen, float, priority, indent)
    else:
        return dummy_handle

def anotate (a, s, l, frozen = True, float = False, priority = 10, indent = 0):
    if has_level(l):
        put('[%s] ' % a, frozen, float, priority, indent)
        h = put(s, frozen, float, priority, indent + 4)
        put('\n', frozen, float, priority)
        return h
    else:
        return dummy_handle

def debug (s = '', frozen = True, float = False, priority = 10, indent = 0):
    return anotate(text.bold_red('DEBUG'), s, DEBUG,
                   frozen, float, priority, indent)

def info (s = '', frozen = True, float = False, priority = 10, indent = 0):
    return anotate(text.bold_blue('*'), s, INFO,
                   frozen, float, priority, indent)

if __pwn__.__libmode__:
    import warnings
    def warning (s = '', frozen = True, float = False, priority = 10, indent = 0):
        warnings.warn(s, stacklevel = 2)
else:
    def warning (s = '', frozen = True, float = False, priority = 10, indent = 0):
        return anotate(text.bold_yello('!'), s, INFO,
                       frozen, float, priority, indent)

def failure (s = '', frozen = True, float = False, priority = 10, indent = 0):
    return anotate(text.bold_red('-'), s, INFO,
                   frozen, float, priority, indent)

def success (s = '', frozen = True, float = False, priority = 10, indent = 0):
    return anotate(text.bold_green('+'), s, INFO,
                   frozen, float, priority, indent)

def indented (s = '', frozen = True, float = False, priority = 10, indent = 0):
    if has_level(INFO):
        h = put(s, frozen, float, priority, indent + 4)
        put('\n', frozen, float, priority)
        return h
    else:
        return dummy_handle

def output (s = '', frozen = True, float = False, priority = 10, indent = 0):
    if has_level(INFO):
        return put(s, frozen, float, priority, indent)
    else:
        return dummy_handle

if __pwn__.__libmode__:
    import exception
    def error (s = '', exit_code = None):
        if sys.exc_type not in [None, KeyboardInterrupt]:
            reason = sys.exc_info()
        else:
            reason = None
        raise exception.PwnlibException(s, reason, exit_code)
else:
    def error (s = '', exit_code = -1):
        anotate(text.on_red('ERROR'), s, ERROR)
        if has_level(INFO) and sys.exc_type not in [None, KeyboardInterrupt]:
            put('The exception was:\n')
            import traceback
            traceback.print_exc()
        sys.exit(exit_code)

def die (s):
    error (s)

def fatal (s = '', exit_code = -1):
    anotate(text.on_red('FATAL'), s, ERROR)
    if has_level(ERROR) and sys.exc_type not in [None, KeyboardInterrupt]:
        put('The exception was:\n')
        import traceback
        traceback.print_exc()
    sys.exit(exit_code)

def bug (s = '', exit_code = -1):
    anotate(text.on_red('BUG (this should not happen)'), s, ERROR)
    if has_level(ERROR) and sys.exc_type not in [None, KeyboardInterrupt]:
        put('The exception was:\n')
        import traceback
        traceback.print_exc()
    sys.exit(exit_code)

def stub (s = '', exit_code = -1):
    if has_level(ERROR):
        import traceback
        filename, lineno, fname, _line = \
            traceback.extract_stack(limit = 2)[0]
        put('Unimplemented function: %s in file "%s", line %d\n' %
            (fname, filename, lineno))
        if s:
            put('%s\n' % s)
    sys.exit(exit_code)

if __pwn__.__libmode__ or __pwn__.__hasrepl__ or not __pwn__.__hasterm__:
    class Handle:
        def __init__ (self, msg, _spinner):
            info('%s...' % msg)
            self.msg = msg
        def status (self, _):
            pass
        def success (self, s = 'OK'):
            success('%s: %s' % (self.msg, s))
        def failure (self, s = 'FAILED!'):
            failure('%s: %s' % (self.msg, s))
else:
    import time
    from ..nonlib import term

    class Spinner(threading.Thread):
        def __init__ (self, spinner):
            threading.Thread.__init__(self)
            self.spinner = spinner
            self.idx = 0
            self.daemon = True
            import sys as _sys
            self.sys = _sys
            self.handle = term.output()
            self.lock = threading.Lock()
            self.start()

        def run (self):
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

        def stop (self, s):
            self.running = False
            with self.lock:
                self.handle.update(s)
                self.handle.freeze()

    class Handle:
        def __init__ (self, msg, spinner):
            self.hasmsg = msg <> ''
            put('[')
            if spinner is None:
                import random, spinners
                spinner = random.choice(spinners.spinners)
            self.spinner = Spinner(spinner)
            put('] %s' % msg)
            self.stat = term.output()
            put('\n')
        def status (self, s):
            if self.hasmsg and s:
                s = ': ' + s
            self.stat.update(s)
        def success (self, s = 'OK'):
            if self.hasmsg and s:
                s = ': ' + s
            self.spinner.stop(text.bold_green('+'))
            self.stat.update(s)
            self.stat.freeze()
        def failure (self, s = 'FAILED!'):
            if self.hasmsg and s:
                s = ': ' + s
            self.spinner.stop(text.bold_red('-'))
            self.stat.update(s)
            self.stat.freeze()

handle_stack = []
def waitfor (msg, status = '', spinner = None):
    h = Handle(msg, spinner)
    if status:
        h.status(status)
    handle_stack.append(h)
    return h

def status (h, s = ''):
    if isinstance(h, Handle):
        h.update(s)
    elif handle_stack:
        s = h
        h = handle_stack.pop()
        h.success(s)
    else:
        error('Not waiting for anything')

def done_success (h = 'Done', s = ''):
    if isinstance(h, Handle):
        h.success(s)
    elif handle_stack:
        s = h
        h = handle_stack.pop()
        h.success(s)
    else:
        error('Not waiting for anything')

def done_failure (h = 'FAILED!', s = ''):
    if isinstance(h, Handle):
        h.failure(s)
    elif handle_stack:
        s = h
        h = handle_stack.pop()
        h.failure(s)
    else:
        error('Not waiting for anything')
