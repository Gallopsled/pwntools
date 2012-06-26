# Debug mode?
import pwn, sys
if 'DEBUG' in sys.argv:
    sys.argv.remove('DEBUG')
    pwn.DEBUG = True
else:
    pwn.DEBUG = False

# Constans
INCLUDE = 'include'

# Submodules
import util, i386, shellcraft

# Promote to top-level
from util import *
