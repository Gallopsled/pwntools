from pwn import memoize, log, md5sumhex
from ctypes import CDLL
from subprocess import Popen, PIPE
import tempfile, os, sys

__tempdir = os.path.join(tempfile.gettempdir(), 'pwn-ciic')
__cache = {}

if not os.path.exists(__tempdir):
    try:
        os.mkdir(__tempdir)
    except:
        log.failure('Could not create memoization dir: %s\n' % __tempdir)
        __tempdir = None
elif not os.path.isdir(__tempdir):
    log.failure('Memoization path is not a dir: %s\n' % __tempdir)
    __tempdir = None

def _compile(code, werror, flags, libs):
    digest = md5sumhex(code + str(werror) + str(flags) + str(libs))
    if digest in __cache:
        return __cache[digest]
    sopath = os.path.join(__tempdir, digest + '.so')
    try:
        if os.path.exists(sopath):
            return CDDL(sopath)
    except:
        pass
    cpath = os.path.join(__tempdir, digest + '.c')
    with open(cpath, 'w') as f:
        f.write(code)
    flags += ['-fPIC', '-shared', '-O3', '-march=native', '-mtune=native',
              '-Wall']
    if werror:
        flags.append('-Werror')
    cmd = ['gcc'] + flags + ['-o', sopath, cpath] + libs
    p = Popen(cmd, stderr = PIPE)
    _, s = p.communicate()
    s = s.replace(cpath + ':', '').replace(cpath, '')
    if p.returncode <> 0:
        log.error('GCC error (%s):' % cpath)
        log.trace(s)
        sys.exit(p.returncode)
    elif s <> '':
        log.warning('GCC warning (%s):' % cpath)
        log.trace(s)
    return CDLL(sopath)

def ciic(code, werror = True, flags = [], libs = []):
    dll = _compile(code, werror, flags, libs)
    return dll
