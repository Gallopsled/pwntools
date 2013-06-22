import pwn

_cache = {}

def _tempdir():
    global _tempdir
    import tempfile, os
    __tempdir = os.path.join(tempfile.gettempdir(), 'pwn-clookup')

    if not os.path.exists(__tempdir):
        try:
            os.mkdir(__tempdir)
        except:
            pwn.log.failure('Could not create memoization dir: %s\n' % __tempdir)
            __tempdir = None
    elif not os.path.isdir(__tempdir):
        pwn.log.failure('Memoization path is not a dir: %s\n' % __tempdir)
        __tempdir = None

    def _tempdir():
        return __tempdir
    return __tempdir

@pwn.need_context
def clookup(*consts, **kwargs):
    consts = pwn.concat_all(consts)
    eval   = kwargs.get('eval', False)
    arch   = kwargs.get('arch', None)
    os     = kwargs.get('os', None)

    if os == None or arch == None:
        return consts

    return _clookup(consts, eval, arch, os)

def _clookup(consts, eval, target_arch, target_os):
    import os, pickle

    comb = target_os + '_' + target_arch

    try:
        return [_cache[comb][1*eval][c] for c in consts]
    except KeyError:
        pass

    cache = ({}, {})

    if _tempdir():
        savefile = os.path.join(_tempdir(), comb)
        if os.path.isfile(savefile):
            with open(savefile) as fd:
                cache = pickle.load(fd)
    else:
        savefile = None

    todo = [c for c in consts if c not in cache[0]]

    if todo:
        found = _clookup_real(todo)

        for c, res in zip(todo, found):
            cache[0][c] = res
            try:
                res = pwn.expr_eval(res)
            except ValueError:
                pass
            cache[1][c] = res

        if savefile:
            with open(savefile, 'w') as fd:
                pickle.dump(cache, fd)

    _cache[comb] = cache

    if eval:
        dict = cache[1]
    else:
        dict = cache[0]

    not_found = [c for c in consts if c not in dict]

    if not_found:
        raise Exception('Could not look up these constants:\n%s' % '\n'.join(not_found))

    return [dict[c] for c in consts]

def _clookup_real(consts):
    import string
    magic = pwn.randoms(32, only = string.ascii_lowercase)
    magic_ = '\n%s\n' % magic
    dat = magic_.join([''] + consts)

    output = pwn.asm(dat, emit_asm = 1)
    output_ = [line.strip() for line in output.split(magic)]

    if len(output_) != len(consts) + 1:
        raise Exception("Unknown output format:\n%s" % output)

    return output_[1:]
