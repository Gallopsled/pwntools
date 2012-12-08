import pwn, md5, os, tempfile
from functools import wraps
from cPickle import load, dump

__tempdir = os.path.join(tempfile.gettempdir(), 'pwn-memoize')
def memoize(f):
    if __tempdir is None:
        return f
    @wraps(f)
    def g(*args, **kwargs):
        digest = md5.md5(str(args) + str(kwargs)).hexdigest()
        fname = os.path.join(__tempdir, digest)
        if os.path.exists(fname):
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

if not os.path.exists(__tempdir):
    try:
        os.mkdir(__tempdir)
    except:
        pwn.trace(' [-] Could not create memoization dir: %s\n' % __tempdir)
        def memoize(f):
            return f
elif not os.path.isdir(__tempdir):
    pwn.trace(' [-] Memoization path is not a dir: %s\n' % __tempdir)
    def memoize(f):
        return f

