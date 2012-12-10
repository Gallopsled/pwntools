# Submodules used in this file (they are deleted at the end)
import os, traceback

# Useful re-exports
from time import sleep
from socket import htons, inet_aton, inet_ntoa, gethostbyname
from os import system
from sys import argv

# Install path
installpath = os.path.dirname(__file__)

# Argument parsing
TRACE = True
DEBUG = False

# Ugly hack to check if argv should be parsed
_do_argv = True
try:
    if 'pwn.noargv' in traceback.extract_stack(limit=2)[0][3]:
        _do_argv = False
except:
    pass

if _do_argv:
    try:
        for _arg in argv[:]:
            if   _arg == 'DEBUG':
                argv.remove(_arg)
                DEBUG = True
            elif _arg == 'NOTRACE':
                argv.remove(_arg)
                TRACE = False
            elif _arg.find('=') > 0:
                key, val = _arg.split('=', 1)
                if not all(x.isupper() for x in key): continue
                argv.remove(_arg)
                globals()[key] = val
    except:
        pass

# Promote to toplevel
from pwn.consts     import *
from pwn.thread     import Thread
from pwn.log        import die
from pwn.util       import *
from pwn.binutils   import *
from pwn.hashes     import *
from pwn.listutil   import *
from pwn.genutil    import *
from pwn.memoize    import memoize
from pwn.process    import process
from pwn.remote     import remote
from pwn.handler    import handler
from pwn.context    import *
from pwn.asm        import asm
from pwn.useragents import randomua
from pwn.splash     import splash

try:
    import pwn.rop
except:
    if DEBUG:
        traceback.print_exc()
    log.warning("rop module could not loaded...")

import pwn.internal.init.session
import pwn.internal.init.cloud
import pwn.sqli
import pwn.shellcodes

# Make pwn.fucking work as pwn by itself
import pwn as fucking

# Clean up namespace by deleting imported modules and local variable
module_type = os.__class__
for k, v in globals().items():
    if isinstance(v, module_type):
        if not v.__name__.startswith('pwn.'):
            del globals()[k]
    elif k.startswith('_') and not k.startswith('__'):
        del globals()[k]
del k, v, module_type

# These modules are not generally useful and
# should only be available when explicitly asked for.
del shellcode_helper, excepthook
