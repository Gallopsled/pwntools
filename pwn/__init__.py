# Promote useful stuff to toplevel
import sys
import pwnlib
from pwnlib                 import *
from pwnlib.asm             import *
from pwnlib.util.binary     import *
from pwnlib.util.iterator   import *
from pwnlib.util.lists      import *
from pwnlib.util.misc       import *
from pwnlib.util.packing    import *
from pwnlib.util.proc       import *

# Put the terminal in raw mode
pwnlib.term.take_ownership()

# default log level in non-lib mode
context.log_level = 'info'

# look for special args in argv
def closure():
    import sys
    if not hasattr(sys, 'argv'):
        return
    import string, collections
    global args
    args = collections.defaultdict(str)
    def isident (s):
        first = string.uppercase + '_'
        body = string.digits + first
        if not s:
            return False
        if s[0] not in first:
            return False
        if not all(c in body for c in s[1:]):
            return False
        return True
    for arg in sys.argv[:]:
        if   arg == 'DEBUG':
            sys.argv.remove(arg)
            context.log_level = 'debug'
        elif arg == 'NOINFO':
            sys.argv.remove(arg)
            context.log_level = 'silent'
        elif arg.find('=') > 0:
            k, v = arg.split('=', 1)
            if not isident(k):
                continue
            sys.argv.remove(arg)
            args[k] = v
closure()
del closure
