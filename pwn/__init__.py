# Submodules
import pwn, os, sys, time, traceback
import platform

# Useful re-exports
from time import sleep
from socket import htons, inet_aton, inet_ntoa, gethostbyname
from os import system
from time import sleep

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
                if not all(x.isupper() for x in key): continue
                sys.argv.remove(_arg)
                pwn.__builtins__[key] = val
    except:
        pass

# Promote to toplevel
from pwn.thread import Thread
from pwn.util       import *
from pwn.binutils   import *
from pwn.hashes     import *
from pwn.listutil   import *
from pwn.excepthook import addexcepthook
from pwn.log        import *
from pwn.memoize    import memoize
from pwn.process    import process
from pwn.remote     import remote
from pwn.handler    import handler
from pwn.context    import *
from pwn.asm        import *
from pwn.shellcodes import *
from pwn.useragents import randomua
from pwn.splash     import splash
from pwn.elf        import ELF
from pwn.rop        import ROP

import pwn.internal.init.session
import pwn.internal.init.cloud
import pwn.sqli
import pwn.rop

# Make pwn.fucking work as pwn by itself
#import pwn as fucking
