"""
Replacement for the Python standard library's atexit.py.

Whereas the standard :mod:`atexit` module only defines :func:`atexit.register`,
this replacement module also defines :func:`unregister`.

This module also fixes a the issue that exceptions raised by an exit handler is
printed twice when the standard :mod:`atexit` is used.
"""

import sys
import threading
import traceback

from .context import context

__all__ = ['register', 'unregister']

_lock = threading.Lock()
_ident = 0
_handlers = {}

def register(func, *args, **kwargs):
    """register(func, *args, **kwargs)

    Registers a function to be called on program termination.  The function will
    be called with positional arguments `args` and keyword arguments `kwargs`,
    i.e. ``func(*args, **kwargs)``.  The current `context` is recorded and will
    be the one used when the handler is run.

    E.g. to suppress logging output from an exit-handler one could write::

      with context.local(log_level = 'error'):
        atexit.register(handler)

    An identifier is returned which can be used to unregister the exit-handler.

    This function can be used as a decorator::

      @atexit.register
      def handler():
        ...

    Notice however that this will bind ``handler`` to the identifier and not the
    actual exit-handler.  The exit-handler can then be unregistered with::

      atexit.unregister(handler)

    This function is thread safe.

    """
    global _ident
    with _lock:
        ident = _ident
        _ident += 1
    _handlers[ident] = (func, args, kwargs, vars(context))
    return ident

def unregister(ident):
    """unregister(ident)

    Remove the exit-handler identified by `ident` from the list of registered
    handlers.  If `ident` isn't registered this is a no-op.
    """
    if ident in _handlers:
        del _handlers[ident]

def _run_handlers():
    """_run_handlers()

    Run registered exit-handlers.  They run in the reverse order of which they
    were registered.

    If a handler raises an exception, it will be printed but nothing else
    happens, i.e. other handlers will be run and `sys.excepthook` will not be
    called for that reason.
    """
    context.clear()
    for _ident, (func, args, kwargs, ctx) in \
        sorted(_handlers.items(), reverse = True):
        try:
            with context.local(**ctx):
                func(*args, **kwargs)
        except SystemExit:
            pass
        except Exception:
            # extract the current exception and rewind the traceback to where it
            # originated
            typ, val, tb = sys.exc_info()
            traceback.print_exception(typ, val, tb.tb_next)

# if there's already an exitfunc registered be sure to run that too
if hasattr(sys, "exitfunc"):
    register(sys.exitfunc)

sys.exitfunc = _run_handlers
