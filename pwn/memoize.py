import pwn

def _tempdir():
    global _tempdir
    import tempfile, os
    __tempdir = os.path.join(tempfile.gettempdir(), 'pwn-memoize')

    if not os.path.exists(__tempdir):
        try:
            os.mkdir(__tempdir)
        except:
            pwn.log.warning('Could not create memoization dir: %s\n' % __tempdir)
            __tempdir = None
    elif not os.path.isdir(__tempdir):
        pwn.log.warning('Memoization path is not a dir: %s\n' % __tempdir)
        __tempdir = None
    def _tempdir():
        return __tempdir
    return __tempdir

def memoize(*args, **kwargs):
    '''Function memoization decorator.
    Args:
    use_mem (default True):   Cache results in memory.
    use_file (default True):  Cache results in files under /tmp/pwn-memoize.

    Used with no arguments is the same as setting mem = True and file = True.'''
    if len(args) == 1 and kwargs == {}:
        return _internal_memoize()(args[0])
    else:
        return _internal_memoize(*args, **kwargs)

_TYPE_VALUE     = 0
_TYPE_EXCEPTION = 1

def _internal_memoize(use_mem = True, use_file = True):
    def real(f):
        if use_mem == False and use_file == False:
            return f

        if use_mem == False or _tempdir() == None:
            return f

        cache = {}

        @pwn.decoutils.ewraps(f)
        def wrapper(*args, **kwargs):
            import os
            from cPickle import load, dump
            sig = (str(args), str(kwargs))
            t = None
            fname = None
            file_miss = False
            dict_miss = False

            try:
                if use_mem:
                    if sig in cache:
                        t, val = cache[sig]
                    else:
                        dict_miss = True

                if t == None and use_file:
                    digest = pwn.md5sumhex('.'.join((f.__module__, f.__name__) + sig))
                    fname = os.path.join(_tempdir(), digest)
                    try:
                        if os.path.exists(fname):
                            with open(fname) as fd:
                                t, val = load(fd)
                        else:
                            file_miss = True
                    except:
                        file_miss = True

                if t == None:
                    try:
                        t, val = _TYPE_VALUE, f(*args, **kwargs)
                    except Exception as e:
                        t, val = _TYPE_EXCEPTION, e
                        raise

                if t == _TYPE_VALUE:
                    return val
                else:
                    raise val
            finally:
                if t != None:
                    if dict_miss:
                        cache[sig] = (t, val)
                    if file_miss:
                        try:
                            with open(fname, 'w') as fd:
                                dump((t, val), fd)
                        except:
                            pass
        return wrapper
    return real

