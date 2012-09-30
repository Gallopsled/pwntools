# Argument parsing
import pwn, sys, time
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

# Constans
INCLUDE = 'include'

# Submodules
import util, i386, os

# Promote to top-level
from util import *

# Promote trace and debug to top-level
from util.log import trace, debug
