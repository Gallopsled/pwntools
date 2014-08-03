"""
Replacement for the Python standard library's atexit.py.

Whereas the standard :mod:`atexit` module only defines :func:`atexit.register`,
this replacement module also defines :func:`unregister`.

This module also fixes a the issue that exceptions raised by an exit handler is
printed twice when the standard :mod:`atexit` is used.
"""

import sys, atexit, traceback

__all__ = ['register', 'unregister']

_handlers = {}

def register(func, *args, **kwargs):
    """register(func, *args, **kwargs)

    Registers a function to be called when an unhandled exception occurs.  The
    function will be called with positional arguments `args` and keyword
    arguments `kwargs`, i.e. ``func(*args, **kwargs)``.

    If `func` is already registered then `args` and `kwargs` will be updated.

    This function can be used as a decorator::

      def f():
        ...
      atexit.register(f)

    is equivalent to this::

      @atexit.register
      def f():
        ...

    """
    _handlers[func] = (args, kwargs)
    return func

def unregister(func):
    """unregister(func)

    Remove `func` from the collection of registered functions.  If `func` isn't
    registered this is a no-op.
    """
    if func in _handlers:
        del _handlers[func]

def _run_handlers():
    """_run_handlers()

    Run registered exit handlers.  The order is arbitrary.

    If a handler raises an exception, it will be printed but nothing else
    happens, i.e. other handlers will be run and `sys.excepthook` will not be
    called for that reason.
    """
    for func, (args, kwargs) in _handlers.items():
        try:
            func(*args, **kwargs)
        except SystemExit:
            pass
        except:
            # extract the current exception and rewind the traceback to where it
            # originated
            typ, val, tb = sys.exc_info()
            traceback.print_exception(typ, val, tb.tb_next)

# as we have imported `atexit` this should be set, but better be safe than sorry
if hasattr(sys, "exitfunc"):
    register(sys.exitfunc)

sys.exitfunc = _run_handlers
