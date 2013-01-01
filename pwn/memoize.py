import pwn, md5, os, tempfile
from pwn import log
from functools import wraps
from cPickle import load, dump

__tempdir = os.path.join(tempfile.gettempdir(), 'pwn-memoize')
__cache = {}
def _internal_memoize(f, mem = True, file = True):
    if __tempdir is None or not (mem or file):
        return f
    @wraps(f)
    def g(*args, **kwargs):
        digest = md5.md5(str(args) + str(kwargs)).hexdigest()
        fname = os.path.join(__tempdir, digest)
        if mem and digest in __cache:
            return __cache[digest]
        elif file and os.path.exists(fname):
            try:
                with open(fname) as fd:
                    y = load(fd)
                return y
            except:
                pass
        y = f(*args, **kwargs)
        if file:
            try:
                with open(fname, 'w') as fd:
                    dump(y, fd)
            except:
                pass
        if mem:
            __cache[digest] = y
        return y
    return g

def memoize(*args, **kwargs):
    '''Function memoization decorator.
    Args:
    mem (default True):  Cache results in memory.
    file (default True):  Cache results in files under /tmp/pwn-memoize.

    Used with no arguments is the same as setting mem = True and file = True.'''
    if len(args) == 1 and kwargs == {}:
        return _internal_memoize(args[0])
    else:
        def deco(f):
            return _internal_memoize(f,
                                     mem = kwargs.get('mem', True),
                                     file = kwargs.get('file', True),
                                    )
        return deco


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

