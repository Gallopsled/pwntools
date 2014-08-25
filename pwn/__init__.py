# Promote useful stuff to toplevel
import sys
from .toplevel import *

# default log level in non-lib mode
context.defaults.log_level = 'info'

# look for special args in argv
def closure():
    term_mode = True
    import sys
    if not hasattr(sys, 'argv'):
        return
    import string, collections
    global args
    args = collections.defaultdict(str)
    def isident(s):
        first = string.uppercase + '_'
        body = string.digits + first
        if not s:
            return False
        if s[0] not in first:
            return False
        if not all(c in body for c in s[1:]):
            return False
        return True
    def asbool(s):
        if   s.lower() == 'true':
            return True
        elif s.lower() == 'false':
            return False
        elif s.isdigit():
            return bool(int(s))
        else:
            raise ValueError('must be integer or boolean')
    # parse environtment variables
    for k, v in os.environ.items():
        if not k.startswith('PWNLIB_'):
            continue
        k = k[7:]
        if   k == 'DEBUG':
            if asbool(v):
                context.log_level = 'debug'
        elif k == 'SILENT':
            if asbool(v):
                context.log_level = 'silent'
        elif k == 'NOTERM':
            if asbool(v):
                term_mode = False
        elif k == 'LOG_LEVEL':
            context.log_level = v
        elif isident(k):
            args[k] = v
    # parse command line
    for arg in sys.argv[:]:
        if   arg == 'DEBUG':
            sys.argv.remove(arg)
            context.log_level = 'debug'
        elif arg == 'SILENT':
            sys.argv.remove(arg)
            context.log_level = 'silent'
        elif arg == 'NOTERM':
            term_mode = False
        elif arg.find('=') > 0:
            k, v = arg.split('=', 1)
            if not isident(k):
                continue
            sys.argv.remove(arg)
            args[k] = v
    # put the terminal in rawmode unless NOTERM was specified
    if term_mode:
        term.init()
closure()
del closure
