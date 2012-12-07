# Submodules
import pwn, os, sys, time, traceback
import platform

# Install path
pwn.installpath = os.path.dirname(__file__)

# Constans
from consts import *

# Argument parsing
pwn.TRACE = True
pwn.DEBUG = False

# argv
pwn.argv = sys.argv

_do_argv = True
try:
    if 'pwn.noargv' in traceback.extract_stack(limit=2)[0][3]:
        _do_argv = False
except:
    pass

if _do_argv:
    try:
        for _arg in sys.argv[:]:
            if   _arg == 'DEBUG':
                sys.argv.remove(_arg)
                pwn.DEBUG = True
            elif _arg == 'NOTRACE':
                sys.argv.remove(_arg)
                pwn.TRACE = False
            elif _arg.find('=') > 0:
                key, val = _arg.split('=', 1)
                if any(map(lambda x: not x.isupper(), key)): continue
                sys.argv.remove(_arg)
                pwn.__builtins__[key] = val
    except:
        pass

# Promote to toplevel
from thread     import Thread
from util       import *
from log        import trace, debug
from excepthook import addexcepthook
from memoize    import memoize
from process    import process
from remote     import remote
from handler    import handler
from asm        import *
from shellcodes import *
try:
    from rop   import *
except:
    log.warning("rop module could not loaded...")

# try:
#     from aeROPics   import aeROPics
# except:
#     log.warning("Could not load aeROPics module, failed loading distorm3 module...")
from useragents import randomua
from splash     import splash

import pwn.internal.init.session
import pwn.internal.init.cloud
import fucking
import sqli
