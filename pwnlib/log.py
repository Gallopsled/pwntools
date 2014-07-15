"""The purpose of this module is to expose a nice API
to wrap around :func:`pwnlib.term.output`.

We have designed it around these considerations:

* It should work both in :data:`pwnlib.term.term_mode` and in normal mode.
* We want log levels.
* We want spinners.
* It should expose all the functionality of :func:`pwnlib.term.output`.

For an explanations of the semantics of the ``frozen``, ``float``, ``priority`` and ``indent``
arguments, see :func:`pwnlib.term.output`.
"""

__all__ = [
    # Constants
    # 'DEBUG', 'INFO', 'ERROR', 'SILENT',

    # loglevel == DEBUG
    'trace', 'debug',

    # loglevel == INFO
    'output', 'info', 'success', 'failure', 'warning', 'indented',

    # loglevel == ERROR
    'error', 'bug', 'fatal', 'stub',

    # spinner-functions (loglevel == INFO)
    'waitfor', 'status', 'done_success', 'done_failure',
]

import threading, sys, time
from . import term, context
from .term import text

#: Loglevel which includes almost everything.
DEBUG  = 10

#: Loglevel which includes most information, but not e.g. calls to :func:`trace`.
INFO   = 20

#: Loglevel which only includes errors.
ERROR  = 30

#: Will supress all normal logging output.
SILENT = 100


_last_was_nl = True
def _put(s = '', frozen = True, float = False, priority = 10, indent = 0):
    global _last_was_nl
    if term.term_mode:
        return term.output(str(s), frozen = frozen, float = float,
                           priority = priority, indent = indent)
    else:
        s = str(s)
        if not s:
            return _dummy_handle
        if _last_was_nl:
            sys.stdout.write(' ' * indent)
            _last_was_nl = False
        if s[-1] == '\n':
            _last_was_nl = True
        if indent:
            s = s[:-1].replace('\n', '\n' + ' ' * indent) + s[-1]
        sys.stderr.write(s)
        return _dummy_handle


def _anotate(a, s, l, frozen = True, float = False, priority = 10, indent = 0):
    if context.log_level <= l:
        _put('[%s] ' % a, frozen, float, priority, indent)
        h = _put(s, frozen, float, priority, indent + 4)
        _put('\n', frozen, float, priority)
        return h
    else:
        return _dummy_handle


def trace(s = '', frozen = True, float = False, priority = 10, indent = 0):
    '''trace(string, frozen = True, float = False, priority = 10, indent = 0) -> handle

    Outputs the given string with loglevel :data:`DEBUG`.

    Args:
      s (str): String to output.
      frozen (bool): If this is True, then the return handle will ignore updates.
      float (bool): If this is True, then the text will be floating.
      priority (int): If the text is floating, then this it its priority.
      indent (int): The indentation of the text.

    Returns:
      A handle to the text, so it can be updated later.
'''
    if context.log_level <= DEBUG:
        return _put(s, frozen, float, priority, indent)
    else:
        return _dummy_handle


def debug(s = '', frozen = True, float = False, priority = 10, indent = 0):
    '''debug(string, frozen = True, float = False, priority = 10, indent = 0) -> handle

    Outputs the given string with loglevel :data:`DEBUG` along with a header.

    Args:
      s (str): String to output.
      frozen (bool): If this is True, then the return handle will ignore updates.
      float (bool): If this is True, then the text will be floating.
      priority (int): If the text is floating, then this it its priority.
      indent (int): The indentation of the text.

    Returns:
      A handle to the text, so it can be updated later.
'''
    return _anotate(text.bold_red('DEBUG'), s, DEBUG,
                    frozen, float, priority, indent)


def output(s = '', frozen = True, float = False, priority = 10, indent = 0):
    '''output(string, frozen = True, float = False, priority = 10, indent = 0) -> handle

    Outputs the given string with loglevel :data:`INFO`.

    Args:
      s (str): String to output.
      frozen (bool): If this is True, then the return handle will ignore updates.
      float (bool): If this is True, then the text will be floating.
      priority (int): If the text is floating, then this it its priority.
      indent (int): The indentation of the text.

    Returns:
      A handle to the text, so it can be updated later.
'''
    if context.log_level <= INFO:
        return _put(s, frozen, float, priority, indent)
    else:
        return _dummy_handle


def info(s = '', frozen = True, float = False, priority = 10, indent = 0):
    '''info(string, frozen = True, float = False, priority = 10, indent = 0) -> handle

    Outputs the given string with loglevel :data:`INFO` along with a header.

    Args:
      s (str): String to output.
      frozen (bool): If this is True, then the return handle will ignore updates.
      float (bool): If this is True, then the text will be floating.
      priority (int): If the text is floating, then this it its priority.
      indent (int): The indentation of the text.

    Returns:
      A handle to the text, so it can be updated later.
'''
    return _anotate(text.bold_blue('*'), s, INFO,
                    frozen, float, priority, indent)


def success(s = '', frozen = True, float = False, priority = 10, indent = 0):
    '''success(string, frozen = True, float = False, priority = 10, indent = 0) -> handle

    Outputs the given string with loglevel :data:`INFO` along with a header.

    Args:
      s (str): String to output.
      frozen (bool): If this is True, then the return handle will ignore updates.
      float (bool): If this is True, then the text will be floating.
      priority (int): If the text is floating, then this it its priority.
      indent (int): The indentation of the text.

    Returns:
      A handle to the text, so it can be updated later.
'''
    return _anotate(text.bold_green('+'), s, INFO,
                    frozen, float, priority, indent)


def failure(s = '', frozen = True, float = False, priority = 10, indent = 0):
    '''failure(string, frozen = True, float = False, priority = 10, indent = 0) -> handle

    Outputs the given string with loglevel :data:`INFO` along with a header.

    Args:
      s (str): String to output.
      frozen (bool): If this is True, then the return handle will ignore updates.
      float (bool): If this is True, then the text will be floating.
      priority (int): If the text is floating, then this it its priority.
      indent (int): The indentation of the text.

    Returns:
      A handle to the text, so it can be updated later.
'''
    return _anotate(text.bold_red('-'), s, INFO,
                    frozen, float, priority, indent)


def warning(s = '', frozen = True, float = False, priority = 10, indent = 0):
    '''warning(string, frozen = True, float = False, priority = 10, indent = 0) -> handle

    If in :data:`pwnlib.term.term_mode`, then outputs the given string
    with loglevel :data:`INFO` along with a header. Otherwise calls :func:`warnings.warn`.

    Args:
      s (str): String to output.
      frozen (bool): If this is True, then the return handle will ignore updates.
      float (bool): If this is True, then the text will be floating.
      priority (int): If the text is floating, then this it its priority.
      indent (int): The indentation of the text.

    Returns:
      A handle to the text, so it can be updated later.
'''
    if term.term_mode:
        return _anotate(text.bold_yello('!'), s, INFO,
                        frozen, float, priority, indent)
    else:
        import warnings
        warnings.warn(s, stacklevel = 2)
        return _dummy_handle


def indented(s = '', frozen = True, float = False, priority = 10, indent = 0):
    '''indented(string, frozen = True, float = False, priority = 10, indent = 0) -> handle

    Indents the given string, then outputs it with loglevel :data:`INFO`.

    Args:
      s (str): String to output.
      frozen (bool): If this is True, then the return handle will ignore updates.
      float (bool): If this is True, then the text will be floating.
      priority (int): If the text is floating, then this it its priority.
      indent (int): The indentation of the text.

    Returns:
      A handle to the text, so it can be updated later.
'''
    if context.log_level <= INFO:
        h = _put(s, frozen, float, priority, indent + 4)
        _put('\n', frozen, float, priority)
        return h
    else:
        return _dummy_handle


def error(s = '', exit_code = -1):
    '''If in :data:`pwnlib.term.term_mode`, then:

    * Outputs the given string with loglevel ERROR along with a header.
    * Outputs a call trace with loglevel :data:`INFO`
    * Exits

    Otherwise it raises a :exc:`pwnlib.exceptions.PwnlibException`.

    Args:
      s (str): The error message.
      exit_code (int): The return code to exit with.
'''
    if term.term_mode:
        _anotate(text.on_red('ERROR'), s, ERROR)
        if context.log_level <= INFO and sys.exc_type not in [None, KeyboardInterrupt]:
            _put('The exception was:\n')
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


def bug(s = '', exit_code = -1):
    '''Outputs the given string with loglevel :data:`ERROR` along with a header and a traceback. It then exits with the given exit code.

    Args:
      s (str): The error message.
      exit_code (int): The return code to exit with.
'''
    _anotate(text.on_red('BUG (this should not happen)'), s, ERROR)
    if context.log_level <= ERROR and sys.exc_type not in [None, KeyboardInterrupt]:
        _put('The exception was:\n')
        import traceback
        traceback.print_exc()
    sys.exit(exit_code)


def fatal(s = '', exit_code = -1):
    '''Outputs the given string with loglevel :data:`ERROR` along with a header and a traceback. It then exits with the given exit code.

    Args:
      s (str): The error message.
      exit_code (int): The return code to exit with.
'''
    _anotate(text.on_red('FATAL'), s, ERROR)
    if context.log_level <= ERROR and sys.exc_type not in [None, KeyboardInterrupt]:
        _put('The exception was:\n')
        import traceback
        traceback.print_exc()
    sys.exit(exit_code)


def stub(s = '', exit_code = -1):
    '''Outputs the given string with loglevel :data:`ERROR` along with a header and information about the unimplemented function.

    Args:
      s (str): The error message.
      exit_code (int): The return code to exit with.
'''
    if context.log_level <= ERROR:
        import traceback
        filename, lineno, fname, _line = \
            traceback.extract_stack(limit = 2)[0]
        _put('Unimplemented function: %s in file "%s", line %d\n' %
            (fname, filename, lineno))
        if s:
            _put('%s\n' % s)
    sys.exit(exit_code)


class _DummyHandle:
    def update(self, _s):
        pass

    def freeze(self):
        pass

    def delete(self):
        pass
_dummy_handle = _DummyHandle()


_waiter_stack = []
class _Waiter(object):
    def _remove(self):
        while self in _waiter_stack:
            _waiter_stack.remove(self)


class _SimpleWaiter(_Waiter):
    def __init__(self, msg, _spinner):
        info('%s...' % msg)
        self.msg = msg

    def status(self, _):
        pass

    def success(self, s = 'OK'):
        success('%s: %s' % (self.msg, s))
        self._remove()

    def failure(self, s = 'FAILED!'):
        failure('%s: %s' % (self.msg, s))
        self._remove()


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
                else:
                    break
            self.idx = (self.idx + 1) % len(self.spinner)
            time.sleep(0.1)

    def stop(self, s):
        self.running = False
        with self.lock:
            self.handle.update(s)
            self.handle.freeze()


class _TermWaiter(_Waiter):
    def __init__(self, msg, spinner):
        self.hasmsg = msg != ''
        _put('[')
        if spinner is None:
            import random, term.spinners as spinners
            spinner = random.choice(spinners.spinners)
        self.spinner = _Spinner(spinner)
        _put('] %s' % msg)
        self.stat = term.output()
        _put('\n')

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
        self._remove()

    def failure(self, s = 'FAILED!'):
        if self.hasmsg and s:
            s = ': ' + s
        self.spinner.stop(text.bold_red('-'))
        self.stat.update(s)
        self.stat.freeze()
        self._remove()


def waitfor(msg, status = '', spinner = None):
    """waitfor(msg, status = '', spinner = None) -> waiter

    Starts a new progress indicator which includes a spinner
    if :data:`pwnlib.term.term_mode` is enabled.

    Args:
      msg (str): The message of the spinner.
      status (str): The initial status of the spinner.
      spinner (list): This should either be a list of strings or None.
         If a list is supplied, then a either element of the list
         is shown in order, with an update occuring every 0.1 second.
         Otherwise a random spinner is chosen.

    Returns:
      A waiter-object that can be updated using :func:`status`, :func:`done_success` or :func:`done_failure`.
"""

    if term.term_mode:
        h = _TermWaiter(msg, spinner)
    else:
        h = _SimpleWaiter(msg, spinner)
    if status:
        h.status(status)
    _waiter_stack.append(h)
    return h


def status(s = '', waiter = None):
    """Updates the status-text of waiter-object without completing it.

    Args:
      s (str): The status message.
      waiter: An optional waiter to update. If none is supplied, the last created one is used.
"""
    if waiter == None and _waiter_stack:
        waiter = _waiter_stack[-1]

    if waiter == None:
        error('Not waiting for anything')

    waiter.status(s)


def done_success(s = 'Done', waiter = None):
    """Updates the status-text of a waiter-object, and then sets it to completed in a successful manner.

    Args:
      s (str): The status message.
      waiter: An optional waiter to update. If none is supplied, the last created one is used.
"""
    if waiter == None and _waiter_stack:
        waiter = _waiter_stack[-1]

    if waiter == None:
        error('Not waiting for anything')

    waiter.success(s)


def done_failure(s = 'FAILED!', waiter = None):
    """Updates the status-text of a waiter-object, and then sets it to completed in a failed manner.

    Args:
      s (str): The status message.
      waiter: An optional waiter to update. If none is supplied, the last created one is used.
"""
    if waiter == None and _waiter_stack:
        waiter = _waiter_stack[-1]

    if waiter == None:
        error('Not waiting for anything')

    waiter.failure(s)
