from __future__ import division
from __future__ import print_function

__all__ = ['get']
import curses
import os
import sys

cache = None

def get(cap, *args, **kwargs):
    default = kwargs.pop('default', '')

    if 'PWNLIB_NOTERM' in os.environ:
        return ''

    # Hack for readthedocs.org
    if 'READTHEDOCS' in os.environ:
        return ''

    if kwargs != {}:
        raise TypeError("get(): No such argument %r" % kwargs.popitem()[0])

    if cache is None:
        init()
    s = cache.get(cap)
    if not s:
        s = curses.tigetstr(cap)
        if s is None:
            s = curses.tigetnum(cap)
            if s == -2:
                s = curses.tigetflag(cap)
                if s == -1:
                    # default to empty string so tparm doesn't fail
                    s = ''
                else:
                    s = bool(s)
        cache[cap] = s
    # if `s' is not set `curses.tparm' will throw an error if given arguments
    if args and s:
        return curses.tparm(s, *args)
    else:
        return s

def init():
    global cache

    # Detect running under Jupyter
    try:
        if get_ipython().__class__.__name__ == 'ZMQInteractiveShell':
            os.environ['PWNLIB_NOTERM'] = '1'
            os.environ['JUPYTER_DETECTED'] ='yes'
    except NameError:
        pass

    if 'PWNLIB_NOTERM' not in os.environ:
        # Fix for BPython
        try:
            curses.setupterm()
        except curses.error as e:
            import traceback
            print('Warning:', ''.join(traceback.format_exception_only(e.__class__, e)), file=sys.stderr)
            print('Terminal features will not be available.  Consider setting TERM variable to your current terminal name (or xterm).', file=sys.stderr)
            os.environ['PWNLIB_NOTERM'] = '1'

    cache = {}
    # Manually add reset sequence into the cache.
    # Can't look it up using tigetstr.
    cache['reset'] = '\x1b[m'
