"""
Analogous to atexit, this module allows the programmer to register functions to
be run if an unhandled exception occurs.
"""
from __future__ import absolute_import
from __future__ import division

import sys
import threading
import traceback

from pwnlib.context import context

__all__ = ['register', 'unregister']

_lock = threading.Lock()
_ident = 0
_handlers = {}

def register(func, *args, **kwargs):
    """register(func, *args, **kwargs)

    Registers a function to be called when an unhandled exception occurs.  The
    function will be called with positional arguments `args` and keyword
    arguments `kwargs`, i.e. ``func(*args, **kwargs)``.  The current `context`
    is recorded and will be the one used when the handler is run.

    E.g. to suppress logging output from an exception-handler one could write::

      with context.local(log_level = 'error'):
        atexception.register(handler)

    An identifier is returned which can be used to unregister the
    exception-handler.

    This function can be used as a decorator::

      @atexception.register
      def handler():
        ...

    Notice however that this will bind ``handler`` to the identifier and not the
    actual exception-handler.  The exception-handler can then be unregistered
    with::

      atexception.unregister(handler)

    This function is thread safe.

    """
    global _ident
    with _lock:
        ident = _ident
        _ident += 1
    _handlers[ident] = (func, args, kwargs, vars(context))
    return ident

def unregister(func):
    """unregister(func)

    Remove `func` from the collection of registered functions.  If `func` isn't
    registered this is a no-op.
    """
    if func in _handlers:
        del _handlers[func]

def _run_handlers():
    """_run_handlers()

    Run registered handlers.  They run in the reverse order of which they were
    registered.

    If a handler raises an exception, it will be printed but nothing else
    happens, i.e. other handlers will be run.
    """
    for _ident, (func, args, kwargs, ctx) in \
        sorted(_handlers.items(), reverse = True):
        try:
            with context.local():
                context.clear()
                context.update(**ctx)
                func(*args, **kwargs)
        except SystemExit:
            pass
        except Exception:
            # extract the current exception and rewind the traceback to where it
            # originated
            typ, val, tb = sys.exc_info()
            traceback.print_exception(typ, val, tb.tb_next)

# we rely on the existing excepthook to print exceptions
_oldhook = getattr(sys, 'excepthook', None)

def _newhook(typ, val, tb):
    """_newhook(typ, val, tb)

    Our excepthook replacement.  First the original hook is called to print the
    exception, then each handler is called.
    """
    if _oldhook:
        _oldhook(typ, val, tb)
    if _run_handlers:
        _run_handlers()

sys.excepthook = _newhook
