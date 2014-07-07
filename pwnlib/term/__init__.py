# promote to this module
from term import output, width, height
from key import get as getkey
from keymap import Keymap
import completer, key, readline, termcap, text

initialized = False

def can_init():
    """This function returns True iff stdout is a tty and we are not inside a
    REPL."""

    import sys
    if not sys.stdout.isatty():
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
    global initialized

    if initialized:
        return

    if not can_init():
        return

    import term, readline
    term.init()
    def update_geometry():
        global height, width
        height = term.height
        width = term.width
    term.on_winch.append(update_geometry)
    readline.init()
    initialized = True
