import pwn, md5, os
from tempfile import gettempdir
from os.path import join, exists, isdir
from cPickle import load, dump

__tempdir = join(gettempdir(), 'pwn-memoize')
def memoize(f):
    if __tempdir is None:
        return f
    def g(*args, **kwargs):
        digest = md5.md5(str(args) + str(kwargs)).hexdigest()
        fname = join(__tempdir, digest)
        if exists(fname):
            try:
                with open(fname) as fd:
                    y = load(fd)
                return y
            except:
                pass
        y = f(*args, **kwargs)
        try:
            with open(fname, 'w') as fd:
                dump(y, fd)
        except:
            pass
        return y
    return g

if not exists(__tempdir):
    try:
        os.mkdir(__tempdir)
    except:
        pwn.trace(' [-] Could not create memoization dir: %s\n' % __tempdir)
        def memoize(f):
            return f
elif not isdir(__tempdir):
    pwn.trace(' [-] Memoization path is not a dir: %s\n' % __tempdir)
    def memoize(f):
        return f

