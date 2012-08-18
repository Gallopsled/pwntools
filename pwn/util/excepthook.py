import pwn, traceback, socket, sys

__excepthooks__ = set()

def addexcepthook(hook):
    __excepthooks__.add(hook)

def __excepthook__(*args):
    traceback.print_exception(*args)
    for hook in __excepthooks__:
        hook(*args)

sys.excepthook = __excepthook__
