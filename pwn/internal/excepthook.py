import sys

__excepthooks__ = set()

def addexcepthook(hook):
    '''Add exception hook.
    In the event of unhandled exceptions each hook will be called with arguments
    (etype, evalue, etb).  A backtrace will be printed as usual.'''
    __excepthooks__.add(hook)

def __excepthook__(*args):
    import traceback
    # The spinner might still be running, but due to pythons
    # global interpreter lock, this is not a problem.
    sys.stderr.write('\n\n')
    traceback.print_exception(*args)
    for hook in __excepthooks__:
        hook(*args)

sys.excepthook = __excepthook__
