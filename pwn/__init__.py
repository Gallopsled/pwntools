# Argument parsing
import pwn, sys
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
        sys.argv.remove(arg)
        pwn[key] = val

def trace(s):
    if pwn.TRACE:
        sys.stdout.write(s)
        sys.stdout.flush()

def debug(s):
    if pwn.DEBUG:
        sys.stderr.write(s)
        sys.stderr.flush()

def die(s = None, exception = None, error_code = -1):
    if s:
        pwn.trace(' [-] FATAL: ' + s + '\n')
    if e:
        pwn.trace(' [-] The exception was:\n' + e)
    exit(error_code)

# Constans
INCLUDE = 'include'

# Submodules
import util, i386

# Promote to top-level
from util import *
