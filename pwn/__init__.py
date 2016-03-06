# Promote useful stuff to toplevel
from .toplevel import *


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
        # install a file logger
        import logging, time
        modes = ('w', 'wb', 'a', 'ab')
        filename = args['LOG_FILE']
        mode = 'a'
        # check if mode was specified as "[filename],[mode]"
        if ',' in filename:
            filename_, mode_ = filename.rsplit(',', 1)
            if mode in modes:
                filename = filename_
                mode = mode_
        # ISO 8601
        dfmt = '%Y-%m-%dT%H:%M:%S'
        # write a "header" to the file, which makes it easier to find the start
        # of a session
        with open(filename, mode) as fd:
            lines = [
                '=' * 78,
                ' Started at %s ' % time.strftime(dfmt),
                ' sys.argv = [',
                ]
            for arg in argv:
                lines.append('   %r,' % arg)
            lines.append(' ]')
            lines.append('=' * 78)
            for line in lines:
                fd.write('=%s=\n' % line.ljust(78))
        # if the mode was 'w' or 'wb' we need to change it to 'a'/'ab' now so
        # the logging module wont overwrite the header
        mode = mode.replace('w', 'a')
        # create a formatter and a handler and install them for the pwnlib root
        # logger (i.e. 'pwnlib')
        handler = logging.FileHandler(filename, mode)
        fmt = '%(asctime)s:%(levelname)s:%(name)s:%(message)s'
        formatter = logging.Formatter(fmt, dfmt)
        handler.setFormatter(formatter)
        logging.root.addHandler(handler)
    # put the terminal in rawmode unless NOTERM was specified
    if term_mode:
        term.init()
    # install a log handler and turn logging all the way up
    import pwnlib.log as log
    import logging
    log.rootlogger.setLevel(logging.DEBUG)
    log.install_default_handler()

closure()
del closure

log = getLogger('pwnlib.exploit')
