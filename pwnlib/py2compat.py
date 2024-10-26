"""
Compatibility layer with python 2, allowing us to write normal code.
Beware, some monkey-patching is done.
"""

import os
import shutil
import sys
try:
    import fcntl
    import termios
except ImportError:
    pass

from collections import namedtuple
from struct import Struct

def py2_monkey_patch(module):
    def decorator(f):
        if sys.version_info < (3,):
            f.__module__ = module.__name__
            setattr(module, f.__name__, f)
    return decorator

# python3 -c 'import shutil,inspect; print(inspect.getsource(shutil.get_terminal_size))'
@py2_monkey_patch(shutil)
def get_terminal_size(fallback=(80, 24)):
    """Get the size of the terminal window.

    For each of the two dimensions, the environment variable, COLUMNS
    and LINES respectively, is checked. If the variable is defined and
    the value is a positive integer, it is used.

    When COLUMNS or LINES is not defined, which is the common case,
    the terminal connected to sys.__stdout__ is queried
    by invoking os.get_terminal_size.

    If the terminal size cannot be successfully queried, either because
    the system doesn't support querying, or because we are not
    connected to a terminal, the value given in fallback parameter
    is used. Fallback defaults to (80, 24) which is the default
    size used by many terminal emulators.

    The value returned is a named tuple of type os.terminal_size.
    """
    # columns, lines are the working values
    try:
        columns = int(os.environ['COLUMNS'])
    except (KeyError, ValueError):
        columns = 0

    try:
        lines = int(os.environ['LINES'])
    except (KeyError, ValueError):
        lines = 0

    # only query if necessary
    if columns <= 0 or lines <= 0:
        try:
            size = os.get_terminal_size(sys.__stdout__.fileno())
        except (AttributeError, ValueError, IOError):
            # stdout is None, closed, detached, or not a terminal, or
            # os.get_terminal_size() is unsupported
            size = os.terminal_size(fallback)
        if columns <= 0:
            columns = size.columns
        if lines <= 0:
            lines = size.lines

    return os.terminal_size((columns, lines))

@py2_monkey_patch(os)
class terminal_size(tuple):
    @property
    def columns(self):
        return self[0]

    @property
    def lines(self):
        return self[1]

    def __repr__(self):
        return 'os.terminal_size(columns=%r, lines=%r)' % self

terminal_size = namedtuple('terminal_size', 'columns lines')

termsize = Struct('HHHH')

@py2_monkey_patch(os)
def get_terminal_size(fd):  # pylint: disable=function-redefined
    arr = b'\0' * termsize.size
    arr = fcntl.ioctl(fd, termios.TIOCGWINSZ, arr)
    lines, columns, xpixel, ypixel = termsize.unpack(arr)
    return os.terminal_size((columns, lines))
