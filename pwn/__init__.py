# Submodules
import pwn, os, sys, time

# Install path
pwn.installpath = os.path.dirname(__file__)

# Argument parsing
pwn.TRACE = True
pwn.DEBUG = False
for _arg in sys.argv:
    if   _arg == 'DEBUG':
        sys.argv.remove(_arg)
        pwn.DEBUG = True
    elif _arg == 'NOTRACE':
        sys.argv.remove(_arg)
        pwn.TRACE = False
    elif _arg.find('=') >= 0:
        key, val = _arg.split('=', 1)
        if any(map(lambda x: not x.isupper(), key)): continue
        sys.argv.remove(_arg)
        pwn[key] = val
del _arg

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
