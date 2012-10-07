# Submodules
import pwn, os, sys, time

# Install path
pwn.installpath = os.path.dirname(__file__)

# Argument parsing
pwn.TRACE = True
pwn.DEBUG = False
for arg in sys.argv:
    if   arg == 'DEBUG':
        sys.argv.remove(arg)
        pwn.DEBUG = True
    elif arg == 'NOTRACE':
        sys.argv.remove(arg)
        pwn.TRACE = False
    elif arg.find('=') >= 0:
        key, val = arg.split('=', 1)
        if any(map(lambda x: not x.isupper(), key)): continue
        sys.argv.remove(arg)
        pwn[key] = val

# Promote to toplevel
from util       import *
from log        import trace, debug
from excepthook import addexcepthook
from memoize    import memoize
from process    import process
from remote     import remote
from handler    import handler

import pwn.internal.init.session
import pwn.internal.init.cloud

# Constans
from consts import *
