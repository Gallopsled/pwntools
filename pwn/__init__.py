# Promote useful stuff to toplevel
from .toplevel import *

log = getLogger('pwnlib.exploit')

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
                context.log_level = 'DEBUG'
        elif k == 'SILENT':
            if asbool(v):
                context.log_level = 'ERROR'
        elif k == 'NOTERM':
            if asbool(v):
                term_mode = False
        elif isident(k):
            args[k] = v
    # parse command line
    # save a copy of argv for the log file header (see below)
    argv = sys.argv[:]
    for arg in argv:
        if   arg == 'DEBUG':
            sys.argv.remove(arg)
            context.log_level = 'DEBUG'
        elif arg == 'SILENT':
            sys.argv.remove(arg)
            context.log_level = 'ERROR'
        elif arg == 'NOTERM':
            term_mode = False
        elif arg.find('=') > 0:
            k, v = arg.split('=', 1)
            if not isident(k):
                continue
            sys.argv.remove(arg)
            args[k] = v
    if 'LOG_LEVEL' in args:
        context.log_level = args['LOG_LEVEL']
    if 'LOG_FILE' in args:
        context.log_file = args['LOG_FILE']
    # put the terminal in rawmode unless NOTERM was specified
    if term_mode:
        term.init()
    # install a log handler and turn logging all the way up
    import pwnlib.log as log
    import logging
    log.install_default_handler()

closure()
del closure
