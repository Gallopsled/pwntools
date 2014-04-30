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
#   In this mode log functions return a handle if `handle = True' is given.
#   This handle can be used to update the text at a later point.  The handle
#   returned from `waitfor' can also be used to update the status text
#
# exc*:
#   In this mode the `error' function will not generate any output, but rather
#   raise an exception of type `PwnlibException'.  If `sys.exc_type' is set then
#   the exceptions `reason' will be set to the last raised exception.
#   The `warning' function will signal warnings using the `warnings' module.

__all__ = ['trace', 'debug', 'info', 'warning', 'failure', 'success',
           'indented', 'output', 'error', 'bug', 'die', 'waitfor', 'status',
           'done_success', 'done_failure', 'inc_indent', 'dec_indent',
           ]

import pwn2, text
from config import MAX_INDENTATION, TAB_WIDTH

# log-levels
DEBUG  = 10  # trace, debug
INFO   = 20  # info, (warning,) failure, success, indented, output, waitfor,
             # status, done_success, done_failure
ERROR  = 30  # error, stub, bug, fatal, die
SILENT = 100 # <nothing>

indentation = 0

def inc_indent (amount = TAB_WIDTH):
    global indentation
    indentation = min(MAX_INDENTATION, indentation + TAB_WIDTH)

def dec_indent (amount = TAB_WIDTH):
    global indentation
    indentation = max(0, indentation - TAB_WIDTH)

# XXX: not thread-safe!
class indent:
    def __init__ (self, offset):
        self.offset = offset
    def __enter__ (self):
        global indentation
        indentation += self.offset
    def __exit__ (self, *args):
        global indentation
        indentation -= self.offset

class loglevel:
    def __init__ (self, new_level):
        self.old_level = level
        self.new_level = new_level
    def __enter__ (self):
        global level
        level = self.new_level
    def __exit__ (self, *args):
        global level
        level = self.old_level

if pwn2.hasterm:
    from ..nonlib import term
    def put (s, indent = None):
        if indent is None:
            indent = indentation
        term.output(s, frozen = True, indent = indent)

    def flush ():
        pass
else:
    import sys
    def put (s, indent = None):
        if indent is None:
            indent = indentation
        sys.stderr.write(' ' * indentation + s)

    def flush ():
        sys.stderr.flush()

# these functions are the same in all modes
def trace (s):
    if level <= DEBUG:
        put(s, 0)
        flush()

def anotate (a, s, l, indent = None):
    if level <= l:
        put('[%s] %s\n' % (a, s), indent)

def debug (s):
    anotate(text.bold_red('DEBUG'), s, DEBUG)

def info (s):
    anotate(text.bold_blue('*'), s, INFO)

if pwn2.libmode:
    import warnings
    def warning (s):
        warnings.warn(s, stacklevel = 2)
else:
    def warning (s):
        if level <= INFO:
            put('[!] %s\n' % s)

def failure (s):
    anotate(text.bold_red('-'), s, INFO)

def success (s):
    anotate(text.bold_green('+'), s, INFO)

def indented (s):
    if level <= INFO:
        put(' ' * 4 + '%s\n')

def output (s):
    if level <= INFO:
        put(s)
        flush(s)

if pwn2.libmode:
    import exception
    def error (s, exit_code = None):
        if sys.exc_type not in [None, KeyboardInterrupt]:
            reason = sys.exc_info()
        else:
            reason = None
        raise exception.PwnlibException(s, reason, exit_code)
else:
    def error (s, exit_code = -1):
        anotate(text.on_red('ERROR'), s, ERROR, 0)
        if level <= INFO and sys.exc_type not in [None, KeyboardInterrupt]:
            put('The exception was:\n', 0)
            import traceback
            traceback.print_exc()
        sys.exit(exit_code)

def die (s):
    error (s)

def fatal (s, exit_code = -1):
    anotate(text.on_red('FATAL'), s, ERROR, 0)
    if level <= ERROR and sys.exc_type not in [None, KeyboardInterrupt]:
        put('The exception was:\n', 0)
        import traceback
        traceback.print_exc()
    sys.exit(exit_code)

def bug (s, exit_code = -1):
    anotate(text.on_red('BUG (this should not happen)'), s, ERROR, 0)
    if level <= ERROR and sys.exc_type not in [None, KeyboardInterrupt]:
        put('The exception was:\n', 0)
        import traceback
        traceback.print_exc()
    sys.exit(exit_code)

def stub (s = '', exit_code = -1):
    if level <= ERROR:
        import traceback
        filename, lineno, fname, _line = \
            traceback.extract_stack(limit = 2)[0]
        put('Unimplemented function: %s in file "%s", line %d\n' %
            (fname, filename, lineno), 0)
        if s:
            put('%s\n' % s, 0)
    sys.exit(exit_code)

if pwn2.libmode or pwn2.hasrepl or not pwn2.hasterm:
    level = ERROR if pwn2.libmode else INFO

    class Handle:
        def __init__ (self, msg):
            info('%s...' % msg)
            self.msg = msg
        def status (self, _):
            pass
        def success (self, s = 'Done'):
            dec_indent()
            success('%s: %s' % (self.msg, s))
        def failure (self, s = 'FAILED!'):
            dec_indent()
            failure('%s: %s' % (self.msg, s))
else:
    # default level in nonlib-mode
    level = INFO
    import threading, time
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
        def __init__ (self, msg):
            put('[')
            self.spinner = Spinner(['/', '-', '\\', '|'])
            put('] %s' % msg, 0)
            self.stat = term.output()
            put('\n', 0)
        def status (self, s):
            if s:
                s = ': ' + s
            self.stat.update(s)
        def success (self, s = 'Done'):
            if s:
                s = ': ' + s
            self.spinner.stop(text.bold_green('+'))
            self.stat.update(s)
            self.stat.freeze()
            dec_indent()
        def failure (self, s = 'FAILED!'):
            if s:
                s = ': ' + s
            self.spinner.stop(text.bold_red('-'))
            self.stat.update(s)
            self.stat.freeze()
            dec_indent()

handle_stack = []
def waitfor (msg, status = ''):
    h = Handle(msg)
    inc_indent()
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
