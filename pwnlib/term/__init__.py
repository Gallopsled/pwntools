from __future__ import absolute_import
from __future__ import division

import sys

from pwnlib.term import completer
from pwnlib.term import key
from pwnlib.term import keymap
from pwnlib.term import readline
from pwnlib.term import term
from pwnlib.term import termcap
from pwnlib.term import text

# Re-exports (XXX: Are these needed?)
output = term.output
width =  term.width
height = term.height
getkey = key.get
Keymap = keymap.Keymap

#: This is True exactly when we have taken over the terminal using :func:`init`.
term_mode = False

def can_init():
    """This function returns True iff stderr is a TTY and we are not inside a
    REPL.  Iff this function returns `True`, a call to :meth:`init` will let
    ``pwnlib`` manage the terminal.
    """

    if sys.platform == 'win32':
        return False

    if not sys.stdout.isatty():
        return False

    # Check for python -i
    if sys.flags.interactive:
        return False

    # Check fancy REPLs
    mods = sys.modules.keys()
    for repl in ['IPython', 'bpython', 'dreampielib', 'jupyter_client._version']:
        if repl in mods:
            return False

    # The standard python REPL will have co_filename == '<stdin>' for some
    # frame. We raise an exception to set sys.exc_info so we can unwind the call
    # stack.
    try:
        raise BaseException
    except BaseException:
        frame = sys.exc_info()[2].tb_frame

    while frame:
        if frame.f_code.co_filename == '<stdin>':
            return False
        frame = frame.f_back

    return True


def init():
    """Calling this function will take over the terminal (iff :func:`can_init`
    returns True) until the current python interpreter is closed.

    It is on our TODO, to create a function to "give back" the terminal without
    closing the interpreter.
    """

    global term_mode

    if term_mode:
        return

    if not can_init():
        return

    term.init()
    def update_geometry():
        global height, width
        height = term.height
        width = term.width
    update_geometry()
    term.on_winch.append(update_geometry)
    readline.init()

    term_mode = True
    text.num_colors = termcap.get('colors', default = 8) or 8
