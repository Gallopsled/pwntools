import pwn, md5, os, tempfile, sys
from pwn import decoutils as _decoutils
from pwn import log
from cPickle import load, dump

__tempdir = os.path.join(tempfile.gettempdir(), 'pwn-memoize')
def memoize(use_mem = True, use_file = True):
    cache = {}
    TYPE_VALUE     = 0
    TYPE_EXCEPTION = 1

    def real(f):
        if use_mem == False and use_file == False:
            return f

        if use_mem == False and __tempdir == None:
            return f

        @_decoutils.ewraps(f)
        def wrapper(*args, **kwargs):
            sig = str(args) + str(kwargs)
            t = None
            file_miss = False
            dict_miss = False

            try:
                if use_mem:
                    if sig in cache:
                        t, val = cache[sig]
                    dict_miss = True

                if t == None and use_file:
                    digest = md5.md5(sig).hexdigest()
                    fname = os.path.join(__tempdir, digest)
                    try:
                        if os.path.exists(fname):
                            with open(fname) as fd:
                                t, val = load(fd)
                    finally:
                        if t == None:
                            file_miss = True
                        pass

                if t == None:
                    try:
                        t, val = TYPE_VALUE, f(*args, **kwargs)
                    except Exception as e:
                        t, val = TYPE_EXCEPTION, e
                        raise

                if t == TYPE_VALUE:
                    return val
                else:
                    raise val
            finally:
                if t != None:
                    if dict_miss:
                        cache[sig] = (t,val)
                    if use_file and file_miss:
                        digest = md5.md5(sig).hexdigest()
                        fname = os.path.join(__tempdir, digest)
                        try:
                            with open(fname, 'w') as fd:
                                dump((t, val), fd)
                        except:
                            pass
        return wrapper
    return real    

if not os.path.exists(__tempdir):
    try:
        os.mkdir(__tempdir)
    except:
        log.trace(' [-] Could not create memoization dir: %s\n' % __tempdir)
        def memoize(f):
            return f
elif not os.path.isdir(__tempdir):
    log.trace(' [-] Memoization path is not a dir: %s\n' % __tempdir)
    def memoize(f):
        return f

