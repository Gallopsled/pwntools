# Submodules used in this file (they are deleted at the end)
import os, traceback

# Useful re-exports
from time import sleep

# Install path
installpath = os.path.dirname(os.path.realpath(__file__))
installpath = os.path.realpath(os.path.join(installpath, '..'))

# Argument parsing
TRACE = True
DEBUG = 0

# Ugly hack to check if argv should be parsed
_do_argv = True
try:
    if 'pwn.noargv' in traceback.extract_stack(limit=2)[0][3]:
        _do_argv = False
except:
    pass

if _do_argv:
    try:
        from sys import argv
        for _arg in argv[:]:
            if   _arg == 'DEBUG':
                argv.remove(_arg)
                DEBUG = 1
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

DEBUG = int(DEBUG)

# Promote to toplevel
try:
    from pwn.log        import die, bug
    from pwn.thread     import Thread
    from pwn.util       import *
    from pwn.ui         import *
    from pwn.avoid      import *
    from pwn.context    import *
    from pwn.binutils   import *
    from pwn.hashes     import *
    from pwn.listutil   import *
    from pwn.iterutil   import *
    from pwn.genutil    import *
    from pwn.decoutils  import coroutine, memleaker
    from pwn.procutil   import *
    from pwn.debugging  import *
    from pwn.memoize    import memoize
    from pwn.process    import process
    from pwn.ssh        import ssh
    from pwn.remote     import remote
    from pwn.handler    import handler
    from pwn.asm        import asm, disasm
    from pwn.useragents import randomua
    from pwn.splash     import splash
    from pwn.elf        import ELF, parse_ldd_output
    from pwn.rop        import ROP
    from pwn.dynelf     import DynELF
    from pwn.ciic       import ciic
    from pwn.memleak    import MemLeak
    from pwn.safeeval   import expr_eval, const_eval
    from pwn.clookup    import clookup
    from pwn.fmtstring  import *

    import pwn.internal.init.session
    import pwn.shellcode
    import pwn.sqli
    import pwn.elf
    import pwn.crypto
except SyntaxError:
    print "If you're happy and you know it, syntax error!"
    print "Syntax error"
    print
    print "If you're happy and you know it, syntax error!"
    print "Syntax error"
    print
    print "If you're happy and you know it, and you really want to show it,"
    print "  if you're happy and you know it, syntax error!"
    print "Syntax error"
    raise

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
