from term import output

owns_terminal = False

def can_take_ownership():
    """This function returns True iff stderr is a tty and we are not inside a
    REPL."""

    import sys
    if not sys.stderr.isatty():
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


def take_ownership():
    global owns_terminal, output

    if owns_terminal:
        return

    if not can_take_ownership():
        return

    import term, readline
    term.init()
    readline.init()
    owns_terminal = True
