# Argument parsing
import pwn, sys
pwn.DEBUG = False
for arg in sys.argv:
    if   arg == 'DEBUG':
        sys.argv.remove(arg)
        pwn.DEBUG = True
    elif arg.startswith('HOST='):
        sys.argv.remove(arg)
        pwn.HOST = arg[5:]

# Constans
INCLUDE = 'include'

# Submodules
import util, i386

# Promote to top-level
from util import *
