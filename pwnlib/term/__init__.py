from . import key, readline, text, termcap, keymap, term
import sys

# Re-exports (XXX: Are these needed?)
output = term.output
width =  term.width
height = term.height
getkey = key.get
Keymap = keymap.Keymap

#: This is True exactly when we have taken over the terminal using :func:`init`.
term_mode = False

def can_init():
    """This function returns True iff stdout is a tty and we are not inside a
    REPL."""

    if not sys.stdout.isatty():
        return False

    # Check for python -i
    if sys.flags.interactive:
        return False

    # Check fancy REPLs
    mods = sys.modules.keys()
    for repl in ['IPython', 'bpython', 'dreampielib']:
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
    """Calling this function will take over the terminal (if :func:`can_init`
    returns True) until the current python interpreter is closed.

    It is on our TODO, to create a function to "give back" the terminal without
    closing the interpreter."""

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
