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
    # loglevel == DEBUG
    'trace', 'debug',

    # loglevel == INFO
    'output', 'info', 'success', 'failure', 'warning', 'indented',

    # loglevel == ERROR
    'error', 'bug', 'fatal', 'stub',

    # spinner-functions (loglevel == INFO)
    'waitfor', 'status', 'done_success', 'done_failure',
]

import threading, sys, time, random, warnings, traceback
from . import term, log_levels, context, exception
from .term import text, spinners

_last_was_nl = True
def _put(log_level, string = '', frozen = True, float = False, priority = 10, indent = 0):
    global _last_was_nl
    if context.log_level > log_level:
        return _dummy_handle
    elif term.term_mode:
        return term.output(str(string), frozen = frozen, float = float,
                           priority = priority, indent = indent)
    else:
        string = str(string)
        if not string:
            return _dummy_handle
        if _last_was_nl:
            sys.stdout.write(' ' * indent)
            _last_was_nl = False
        if string[-1] == '\n':
            _last_was_nl = True
        if indent:
            string = string[:-1].replace('\n', '\n' + ' ' * indent) + string[-1]
        sys.stdout.write(string)
        return _dummy_handle


def _anotate(l, a, string, frozen = True, float = False, priority = 10, indent = 0):
    _put(l, '[%s] ' % a, frozen, float, priority, indent)
    h = _put(l, string, frozen, float, priority, indent + 4)
    _put(l, '\n', frozen, float, priority)
    return h

def _good_exc():
    exc = sys.exc_info()
    if not exc or exc[0] in [None, KeyboardInterrupt]:
        return None
    else:
        return exc

def trace(string = '', log_level = log_levels.DEBUG, frozen = True, float = False, priority = 10, indent = 0):
    '''trace(string = '', log_level = DEBUG, frozen = True, float = False, priority = 10, indent = 0) -> handle

    Outputs the given string with the default loglevel :data:`pwnlib.log_levels.DEBUG`.

    Args:
      string (str): String to output.
      log_level(int): The log level to output the text to.
      frozen (bool): If this is True, then the return handle will ignore updates.
      float (bool): If this is True, then the text will be floating.
      priority (int): If the text is floating, then this it its priority.
      indent (int): The indentation of the text.

    Returns:
      A handle to the text, so it can be updated later.
'''
    return _put(log_level, string, frozen, float, priority, indent)


def debug(string = '', log_level = log_levels.DEBUG, frozen = True, float = False, priority = 10, indent = 0):
    '''debug(string = '', log_level = DEBUG, frozen = True, float = False, priority = 10, indent = 0) -> handle

    Outputs the given string with the default loglevel :data:`pwnlib.log_levels.DEBUG` along with a header.

    Args:
      string (str): String to output.
      log_level(int): The log level to output the text to.
      frozen (bool): If this is True, then the return handle will ignore updates.
      float (bool): If this is True, then the text will be floating.
      priority (int): If the text is floating, then this it its priority.
      indent (int): The indentation of the text.

    Returns:
      A handle to the text, so it can be updated later.
'''
    return _anotate(log_level, text.bold_red('DEBUG'), string,
                    frozen, float, priority, indent)


def output(string = '', log_level = log_levels.INFO, frozen = True, float = False, priority = 10, indent = 0):
    '''output(string = '', log_level = INFO, frozen = True, float = False, priority = 10, indent = 0) -> handle

    Outputs the given string with the default loglevel :data:`pwnlib.log_levels.INFO`.

    Args:
      string (str): String to output.
      log_level(int): The log level to output the text to.
      frozen (bool): If this is True, then the return handle will ignore updates.
      float (bool): If this is True, then the text will be floating.
      priority (int): If the text is floating, then this it its priority.
      indent (int): The indentation of the text.

    Returns:
      A handle to the text, so it can be updated later.
'''
    return _put(log_level, string, frozen, float, priority, indent)


def info(string = '', log_level = log_levels.INFO, frozen = True, float = False, priority = 10, indent = 0):
    '''info(string = '', log_level = INFO, frozen = True, float = False, priority = 10, indent = 0) -> handle

    Outputs the given string with the default loglevel :data:`pwnlib.log_levels.INFO` along with a header.

    Args:
      s (str): String to output.
      log_level(int): The log level to output the text to.
      frozen (bool): If this is True, then the return handle will ignore updates.
      float (bool): If this is True, then the text will be floating.
      priority (int): If the text is floating, then this it its priority.
      indent (int): The indentation of the text.

    Returns:
      A handle to the text, so it can be updated later.
'''
    return _anotate(log_level, text.bold_blue('*'), string,
                    frozen, float, priority, indent)


def success(string = '', log_level = log_levels.INFO, frozen = True, float = False, priority = 10, indent = 0):
    '''success(string = '', log_level = INFO, frozen = True, float = False, priority = 10, indent = 0) -> handle

    Outputs the given string with the default loglevel :data:`pwnlib.log_levels.INFO` along with a header.

    Args:
      s (str): String to output.
      frozen (bool): If this is True, then the return handle will ignore updates.
      float (bool): If this is True, then the text will be floating.
      priority (int): If the text is floating, then this it its priority.
      indent (int): The indentation of the text.

    Returns:
      A handle to the text, so it can be updated later.
'''
    return _anotate(log_level, text.bold_green('+'), string,
                    frozen, float, priority, indent)


def failure(string = '', log_level = log_levels.INFO, frozen = True, float = False, priority = 10, indent = 0):
    '''failure(string = '', log_level = INFO, frozen = True, float = False, priority = 10, indent = 0) -> handle

    Outputs the given string with the default loglevel :data:`pwnlib.log_levels.INFO` along with a header.

    Args:
      string (str): String to output.
      log_level(int): The log level to output the text to.
      frozen (bool): If this is True, then the return handle will ignore updates.
      float (bool): If this is True, then the text will be floating.
      priority (int): If the text is floating, then this it its priority.
      indent (int): The indentation of the text.

    Returns:
      A handle to the text, so it can be updated later.
'''
    return _anotate(log_level, text.bold_red('-'), string,
                    frozen, float, priority, indent)


def warning(string = '', log_level = log_levels.INFO, frozen = True, float = False, priority = 10, indent = 0):
    '''warning(string, frozen = True, float = False, priority = 10, indent = 0) -> handle

    If in :data:`pwnlib.term.term_mode`, then outputs the given string
    with the default loglevel :data:`pwnlib.log_levels.INFO` along with a header. Otherwise
    calls :func:`warnings.warn`.

    Args:
      string (str): String to output.
      log_level(int): The log level to output the text to.
      frozen (bool): If this is True, then the return handle will ignore updates.
      float (bool): If this is True, then the text will be floating.
      priority (int): If the text is floating, then this it its priority.
      indent (int): The indentation of the text.

    Returns:
      A handle to the text, so it can be updated later.
'''
    if term.term_mode:
        return _anotate(log_level, text.bold_yellow('!'), string,
                        frozen, float, priority, indent)
    else:
        warnings.warn(string, stacklevel = 2)
        return _dummy_handle


def indented(string = '', log_level = log_levels.INFO, frozen = True, float = False, priority = 10, indent = 0):
    '''indented(string, frozen = True, float = False, priority = 10, indent = 0) -> handle

    Indents the given string, then outputs it with loglevel :data:`pwnlib.log_levels.INFO`.

    Args:
      string (str): String to output.
      log_level(int): The log level to output the text to.
      frozen (bool): If this is True, then the return handle will ignore updates.
      float (bool): If this is True, then the text will be floating.
      priority (int): If the text is floating, then this it its priority.
      indent (int): The indentation of the text.

    Returns:
      A handle to the text, so it can be updated later.
'''
    h = _put(log_level, string, frozen, float, priority, indent + 4)
    _put(log_level, '\n', frozen, float, priority)
    return h


def error(string = '', exit_code = -1):
    '''If in :data:`pwnlib.term.term_mode`, then:

    * Outputs the given string with loglevel :data:`pwnlig.log_levels.ERROR` along with a header.
    * Outputs a call trace with loglevel :data:`pwnlib.log_levels.INFO`
    * Exits

    Otherwise it raises a :exc:`pwnlib.exception.PwnlibException`.

    Args:
      string (str): The error message.
      exit_code (int): The return code to exit with.
'''
    if term.term_mode:
        _anotate(log_levels.ERROR, text.on_red('ERROR'), string)
        if _good_exc():
            _put(log_levels.INFO, 'The exception was:\n')
            _put(log_levels.INFO, traceback.format_exc())
        sys.exit(exit_code)
    else:
        reason = _good_exc()
        raise exception.PwnlibException(string, reason, exit_code)


def bug(string = '', exit_code = -1, log_level = log_levels.ERROR):
    '''Outputs the given string with the default loglevel :data:`pwnlig.log_levels.ERROR` along
    with a header and a traceback. It then exits with the given exit code.

    Args:
      string (str): The error message.
      exit_code (int): The return code to exit with.
      log_level(int): The log level to output the text to.
'''
    _anotate(log_level, text.on_red('BUG (this should not happen)'), string)
    if _good_exc():
        _put(log_level, 'The exception was:\n')
        _put(log_level, traceback.format_exc())
    sys.exit(exit_code)


def fatal(string = '', exit_code = -1, log_level = log_levels.ERROR):
    '''Outputs the given string with the default loglevel :data:`pwnlig.log_levels.ERROR` along
    with a header and a traceback. It then exits with the given exit code.

    Args:
      string (str): The error message.
      exit_code (int): The return code to exit with.
      log_level(int): The log level to output the text to.
'''
    _anotate(log_level, text.on_red('FATAL'), string)
    if _good_exc():
        _put(log_level, 'The exception was:\n')
        _put(log_level, traceback.format_exc())
    sys.exit(exit_code)


def stub(string = '', exit_code = -1, log_level = log_levels.ERROR):
    '''Outputs the given string with the default loglevel :data:`pwnlig.log_levels.ERROR` along
    with a header and information about the unimplemented function.

    Args:
      s (str): The error message.
      exit_code (int): The return code to exit with.
      log_level(int): The log level to output the text to.
'''
    filename, lineno, fname, _line = traceback.extract_stack(limit = 2)[0]
    _put(log_level, 'Unimplemented function: %s in file "%s", line %d\n' %
         (fname, filename, lineno))
    if string:
        _put(log_level, '%s\n' % string)
    sys.exit(exit_code)


class _DummyHandle(object):
    def update(self, _string):
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

class _DummyWaiter(_Waiter):
    def status(self, _):
        pass

    def success(self, string = 'OK'):
        pass

    def failure(self, string = 'FAILED!'):
        pass

class _SimpleWaiter(_Waiter):
    def __init__(self, msg, _spinner, log_level):
        self.log_level = log_level
        info('%s...' % msg, log_level = self.log_level)
        self.msg = msg

    def status(self, _):
        pass

    def success(self, string = 'OK'):
        success('%s: %s' % (self.msg, string), log_level = self.log_level)
        self._remove()

    def failure(self, string = 'FAILED!'):
        failure('%s: %s' % (self.msg, string), log_level = self.log_level)
        self._remove()


class _Spinner(threading.Thread):
    def __init__(self, spinner, log_level):
        threading.Thread.__init__(self)
        self.spinner = spinner
        self.idx = 0
        self.daemon = True
        self.sys = sys
        self.handle = _put(log_level, '', frozen = False)
        self.lock = threading.Lock()
        self.running = True
        self.start()

    def run(self):
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

    def stop(self, string):
        self.running = False
        with self.lock:
            self.handle.update(string)
            self.handle.freeze()


class _TermWaiter(_Waiter):
    def __init__(self, msg, spinner, log_level):
        self.hasmsg = msg != ''
        _put(log_level, '[')
        if spinner is None:
            spinner = random.choice(spinners.spinners)
        self.spinner = _Spinner(spinner, log_level)
        _put(log_level, '] %s' % msg)
        self.stat = _put(log_level, '', frozen = False)
        _put(log_level, '\n')

    def status(self, string):
        if self.hasmsg and string:
            string = ': ' + string
        self.stat.update(string)

    def success(self, string = 'OK'):
        if self.hasmsg and string:
            string = ': ' + string
        self.spinner.stop(text.bold_green('+'))
        self.stat.update(string)
        self.stat.freeze()
        self._remove()

    def failure(self, string = 'FAILED!'):
        if self.hasmsg and string:
            string = ': ' + string
        self.spinner.stop(text.bold_red('-'))
        self.stat.update(string)
        self.stat.freeze()
        self._remove()


def waitfor(msg, status = '', spinner = None, log_level = log_levels.INFO):
    """waitfor(msg, status = '', spinner = None) -> waiter

    Starts a new progress indicator which includes a spinner
    if :data:`pwnlib.term.term_mode` is enabled. By default it
    outputs to loglevel :data:`pwnlib.log_levels.INFO`.

    Args:
      msg (str): The message of the spinner.
      status (str): The initial status of the spinner.
      spinner (list): This should either be a list of strings or None.
         If a list is supplied, then a either element of the list
         is shown in order, with an update occuring every 0.1 second.
         Otherwise a random spinner is chosen.
      log_level(int): The log level to output the text to.

    Returns:
      A waiter-object that can be updated using :func:`status`, :func:`done_success` or :func:`done_failure`.
"""

    if context.log_level > log_level:
        h = _DummyWaiter()
    elif term.term_mode:
        h = _TermWaiter(msg, spinner, log_level)
    else:
        h = _SimpleWaiter(msg, spinner, log_level)

    if status:
        h.status(status)

    _waiter_stack.append(h)
    return h


def status(string = '', waiter = None):
    """Updates the status-text of waiter-object without completing it.

    Args:
      string (str): The status message.
      waiter: An optional waiter to update. If none is supplied, the last created one is used.
"""
    if waiter == None and _waiter_stack:
        waiter = _waiter_stack[-1]

    if waiter == None:
        error('Not waiting for anything')

    waiter.status(string)


def done_success(string = 'Done', waiter = None):
    """Updates the status-text of a waiter-object, and then sets it to completed in a successful manner.

    Args:
      string (str): The status message.
      waiter: An optional waiter to update. If none is supplied, the last created one is used.
"""
    if waiter == None and _waiter_stack:
        waiter = _waiter_stack[-1]

    if waiter == None:
        error('Not waiting for anything')

    waiter.success(string)


def done_failure(string = 'FAILED!', waiter = None):
    """Updates the status-text of a waiter-object, and then sets it to completed in a failed manner.

    Args:
      string (str): The status message.
      waiter: An optional waiter to update. If none is supplied, the last created one is used.
"""
    if waiter == None and _waiter_stack:
        waiter = _waiter_stack[-1]

    if waiter == None:
        error('Not waiting for anything')

    waiter.failure(string)
