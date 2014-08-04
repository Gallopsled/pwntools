"""
Logging module for printing status during an exploit, and internally
within ``pwntools``.

Exploit Developers
------------------
By using the standard ``from pwn import *``, an object named ``log`` will
be inserted into the global namespace.  You can use this to print out
status messages during exploitation.

For example,::

    log.info('Hello, world!')

prints::

    [*] Hello, world!

Additionally, there are some nifty mechanisms for performing status updates
on a running job (e.g. when brute-forcing).::

    p = log.progress('Working')
    p.status('Reticulating splines')
    time.sleep(1)
    p.success('Got a shell!')


The verbosity of logging can be most easily controlled by setting
``context.log_level`` on the global ``context`` object.::

    log.info("No you see me")
    context.log_level = 'error'
    log.info("Now you don't")

Pwnlib Developers
-----------------
A module-specific logger can be imported into the module via

::
    log = logging.getLogger(__name__)

This provides an easy way to filter logging programmatically
or via a configuration file for debugging.

There's no need to expressly import this ``log`` module.

When using ``waitfor``/``progress``, you should use the ``with``
keyword to manage scoping, to ensure the spinner stops if an
exception is thrown.
"""


__all__ = [
    # loglevel == DEBUG
    'debug',

    # loglevel == INFO
    'info', 'success', 'failure', 'warning', 'indented',

    # loglevel == ERROR
    'error', 'bug', 'fatal',

    # spinner-functions (loglevel == INFO)
    'waitfor', 'progress'
]

import logging, re, threading, sys, random
from .context import context, Thread
from .term    import spinners, text
from .        import term

class Logger(logging.getLoggerClass()):
    """
    Specialization of ``logging.Logger`` which uses
    ``pwnlib.context.context.log_level`` to infer verbosity.

    Also adds some ``pwnlib`` flavor via:

    * ``success``
    * ``failure``
    * ``indented``

    Additionally adds ``pwnlib``-specific information for coloring and indentation.

    Finally, it permits prepending a string to each message, by means of
    :attr:`msg_prefix`.  This is leveraged for progress messages.
    """
    def __init__(self, *args, **kwargs):
        super(Logger, self).__init__(*args, **kwargs)
        self.msg_prefix = ''

    def getEffectiveLevel(self):
        normLevel = super(Logger, self).getEffectiveLevel()
        return min(normLevel, context.log_level)

    def __log(self, level, msg, args, kwargs, symbol='', stop=False):
        """
        Creates a named logger, which captures metadata about the
        calling log level, line prefixes, and desired color information.

        Note:
            It's important that only metadata be added to the record, and
            that the message is not changed.
        """
        extra = kwargs.get('extra', {})
        extra.setdefault('pwnlib_symbol', symbol)
        extra.setdefault('pwnlib_stop', stop)
        kwargs['extra'] = extra

        super(Logger,self).log(level, self.msg_prefix + msg, *args, **kwargs)

    def indented(self, m, level=logging.INFO, *a, **kw):
        return self.__log(level, m, a, kw)

    def error(self, m, *a, **kw):
        return self.__log(logging.ERROR, m, a, kw, text.on_red('ERROR'))

    def warn(self, m, *a, **kw):
        return self.__log(logging.WARN, m, a, kw, text.bold_yellow('!'))
    def info(self, m, *a, **kw):
        return self.__log(logging.INFO, m, a, kw, text.bold_blue('*'))

    def success(self, m='Done', *a, **kw):
        return self.__log(logging.INFO, m, a, kw, text.bold_green('+'), True)

    def failure(self, m='Failed', *a, **kw):
        return self.__log(logging.INFO, m, a, kw, text.bold_red('-'), True)

    def debug(self, m, *a, **kw):
        return self.__log(logging.DEBUG, m, a, kw, text.bold_red('DEBUG'), True)

    def progress(self, *args, **kwargs):
        """
        Wrapper around :func:`progress` to enable legacy compatibility with invoking
        ``log.waitfor``.
        """
        return progress(*args, **kwargs)

    done_failure = failure
    done_success = success
    indent = indented
    output = info
    status = info
    waitfor = progress
    warning = warn



class StdoutHandler(logging.Handler):
    """
    For no apparent reason, logging.StreamHandler(sys.stdout)
    breaks all of the fancy output formatting.

    So we bolt this on.
    """
    def emit(self, record):
        self.acquire()
        msg = self.format(record)
        sys.stdout.write('%s\n' % msg)
        self.release()


class PrefixIndentFormatter(logging.Formatter):
    """
    Logging formatter which performs prefixing based on a pwntools-
    specific key, as well as indenting all secondary lines.

    Specifically, it performs the following actions:

    * If the record contains the attribute ``pwnlib_symbol``,
      it is prepended to the message.
    * The message is prefixed such that it starts on column four.
    * If the message spans multiple lines they are split, and all subsequent
      lines are indented.
    """

    # Indentation from the left side of the terminal.
    # All log messages will be indented at list this far.
    indent    = '    '

    # Newline, followed by an indent.  Used to wrap multiple lines.
    nlindent  = '\n' + indent

    def __init__(self, *args, **kwargs):
        super(PrefixIndentFormatter, self).__init__(*args,**kwargs)


    def format(self, record):
        msg = super(PrefixIndentFormatter, self).format(record)

        # Get the per-record prefix second, adjust it to the same
        # width as normal indentation.
        symbol = self.indent
        if record.pwnlib_symbol:
            symbol = '[%s] ' % record.pwnlib_symbol


        msg     = symbol + msg

        # Join all of the lines together so that second lines
        # are properly wrapped
        msg = self.nlindent.join(msg.splitlines())

        return msg


##
# This following snippet probably belongs in pwnlib.term.text, but someone
# decided that it should be a magic module, so I don't want to mess with it.
##

# Matches ANSI escape codes
ansi_escape = re.compile(r'\x1b[^m]*m')

def ansilen(sz):
    """
    Length helper which does not count ANSI escape codes.

    Regex stolen from stackoverflow.com/q/14693701
    """
    return len(ansi_escape.sub('', sz))


#
# Note that ``Logger`` inherits from ``logging.getLoggerClass()``,
# and always invokes the parent class's routines to enrich the data.
#
# Ensure all other instantiated loggers also enrich the data, so that
# our custom handlers could (theoretically) be used with those.
#
logging.setLoggerClass(Logger)


#
# By default, everything will log to the console.
#
# Logging cascades upward through the heirarchy,
# so the only point that should ever need to be
# modified is the root 'pwn' logger.
#
# For example:
#     map(logger.removeHandler, logger.handlers)
#     logger.addHandler(myCoolPitchingHandler)
#
console   = StdoutHandler()
console.setFormatter(PrefixIndentFormatter())

#
# The root 'pwnlib' handler is declared here, and attached to the
# console.  To change the target of all 'pwntools'-specific
# logging, only this logger needs to be changed.
#
logger    = logging.getLogger('pwnlib')
logger.addHandler(console)


#
# Handle legacy log invocation on the 'log' module itself.
# These are so that things don't break.
#
# The correct way to perform logging moving forward for an
# exploit is:
#
#     #!/usr/bin/env python
#     context(...)
#     log = logging.getLogger('pwnlib.exploit.name')
#     log.info("Hello, world!")
#
# And for all internal pwnlib modules, replace:
#
#     from . import log
#
# With
#
#     import logging
#     logging.getLogger(__name__) # => 'pwnlib.tubes.ssh'
#
indented = logger.indented
error    = logger.error
warn     = logger.warn
warning  = logger.warning
info     = logger.info
status   = logger.status
success  = logger.success
failure  = logger.failure
output   = logger.output
debug    = logger.debug
done_success = logger.done_success
done_failure = logger.done_failure


#
# Handle legacy log levels which really should be exceptions
#
def bug(msg):       raise Exception(msg)
def fatal(msg):     raise SystemExit(msg)

class TermPrefixIndentFormatter(PrefixIndentFormatter):
    """
    Log formatter for progress aka 'waitfor' log message, when
    using terminal mode.

    Performs a subset of the formatting of the parent class while
    the spinner is running since the spinner should replace the
    prefix.

    Otherwise, performs a pass-through.
    """
    def format(self, record):
        # Don't do level-specific prefixes unless it's final
        if not getattr(record, 'pwnlib_stop', False):
            return self.nlindent.join(record.msg.splitlines())

        # Return the original formatted message
        return super(TermPrefixIndentFormatter, self).format(record)

class TermHandler(logging.Handler):
    """
    Log handler for a progress aka 'waitfor' log message, when
    using terminal mode.

    Creates a thread to animate the spinner in :func:`spin`,
    and updates the message following it whenever a message
    is emitted.
    """
    def __init__(self, msg='', *args, **kwargs):
        """
        Initialize a TermHandler with a message to be prepended
        to all log message.

        Arguments:
            msg(str): Message to prepend to all log messages
        """
        super(TermHandler, self).__init__(*args, **kwargs)
        self.stop    = threading.Event()
        self.spinner = context.thread(target=self.spin, args=[term.output('')])
        self.spinner.daemon = True
        self.spinner.start()
        self._handle = term.output('')

    def emit(self, record):
        if getattr(record, 'pwnlib_stop', False):
            self.stop.set()
            self.spinner.join()

        msg = self.format(record)
        self._handle.update(msg + '\n')

    def spin(self, handle):
        state  = 0
        states = random.choice(spinners.spinners)

        while not self.stop.wait(0.1):
            handle.update('[' + text.bold_blue(states[state]) + '] ')
            state += 1
            state %= len(states)
        handle.update('')

def _monkeypatch(obj, enter, exit):
    """
    Python, why do you hate me so much?

    >>> class A(object): pass
    ...
    >>> a = A()
    >>> a.__len__ = lambda: 3
    >>> a.__len__()
    3
    >>> len(a)
    Traceback (most recent call last):
    ...
    TypeError: object of type 'A' has no len()
    """
    class Monkey(obj.__class__):
        def __enter__(self, *a, **kw):
            enter(*a, **kw)
            return self
        def __exit__(self, *a, **kw):
            exit(*a, **kw)
    obj.__class__ = Monkey


def waitfor(msg, status = '', log_level = logging.INFO):
    """waitfor(msg, status = '', spinner = None) -> Logger

    Starts a new progress logger which includes a spinner
    if :data:`pwnlib.term.term_mode` is enabled.

    Args:
      msg (str): The message of the spinner.
      status (str): The initial status of the spinner.

    Returns:
      A Logger which can be interacted with in the normal ways via
      ``info`` or ``warn`` etc.

      The spinner is stopped once ``success`` or ``failure`` are invoked
      on the ``Logger``.
    """
    # Create the logger
    name = 'pwnlib.spinner.%i' % waitfor.spin_count
    l    = logging.getLogger(name)
    waitfor.spin_count += 1

    # If we're doing terminal-aware stuff, it'll use the spinners
    # Otherwise, the message will propagate to the root handler
    #
    # Additionally, set __enter__ and __exit__ so that we can use
    # the object as a context handler for the status.
    if term.term_mode and l.isEnabledFor(log_level):
        h = TermHandler()
        h.setFormatter(TermPrefixIndentFormatter())
        l.addHandler(h)
        l.propagate = False

        def stop(*a):
            if not h.stop.isSet():
                l.failure('Done, did not provide status')
                h.stop.set()
        _monkeypatch(l, lambda *a: l, stop)
    else:
        _monkeypatch(l, lambda *a: l, lambda *a: None)

    # Set the prefix on the logger itself
    l.msg_prefix = msg + ': '
    l.info(status)
    return l

waitfor.spin_count = 0
progress = waitfor
