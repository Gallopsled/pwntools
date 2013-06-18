import pwn

def _tempdir():
    global _tempdir
    import tempfile, os
    __tempdir = os.path.join(tempfile.gettempdir(), 'pwn-ciic')

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

__cache = {}

def _compile(code, werror, flags, libs):
    from ctypes import CDLL
    import subprocess, sys, os
    digest = pwn.md5sumhex(code + str(werror) + str(flags) + str(libs))
    if digest in __cache:
        return __cache[digest]
    sopath = os.path.join(_tempdir(), digest + '.so')
    try:
        if os.path.exists(sopath):
            return CDLL(sopath)
    except:
        pass
    cpath = os.path.join(_tempdir(), digest + '.c')
    with open(cpath, 'w') as f:
        f.write(code)
    flags += ['-fPIC', '-shared', '-O3', '-march=native', '-mtune=native',
              '-Wall']
    if werror:
        flags.append('-Werror')
    cmd = ['gcc'] + flags + ['-o', sopath, cpath] + libs
    p = subprocess.Popen(cmd, stderr = subprocess.PIPE)
    _, s = p.communicate()
    s = s.replace(cpath + ':', '').replace(cpath, '')
    if p.returncode <> 0:
        pwn.log.error('GCC error (%s):' % cpath)
        pwn.log.trace(s)
        sys.exit(p.returncode)
    elif s <> '':
        pwn.log.warning('GCC warning (%s):' % cpath)
        pwn.log.trace(s)
    return CDLL(sopath)

def ciic(code, werror = True, flags = [], libs = []):
    dll = _compile(code, werror, flags, libs)
    return dll
