import pwn, subprocess, os, sys, warnings, inspect, errno

INCLUDE = os.path.join(os.path.dirname(pwn.__file__), pwn.INCLUDE)
DEBUG   = pwn.DEBUG

# Supress tmpnam warning
warnings.filterwarnings('ignore', category=RuntimeWarning)

def gen_assembler(hdr, assembler):
    def assemble(*pieces, **rest):
        if 'emit_asm' in rest:
            emit_asm = rest['emit_asm']
        else:
            emit_asm = False
        src = os.tmpnam()
        cmd = assembler(src)
        code = '\n'.join([hdr] + list(pieces))

        if emit_asm:
            return \
                ';;; Assemble with:\n;;;  %s\n' % \
                ' '.join(assembler('<file>')) + code

        with open(src, 'w') as f:
            f.write(code)

        try:
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except OSError, e:
            if e.errno == errno.ENOENT:
                pwn.die(cmd[0] + ' is not installed')
            else:
                raise
        ret = p.wait()
        if ret <> 0:
            err = p.stderr.read()
            sys.stdout.write(err)
            sys.exit(0)
        os.unlink(src)
        return p.stdout.read()
    return pwn.memoize(assemble)

def load(codes):
    globs = inspect.currentframe(1).f_globals
    base = globs['__name__']
    for c in codes:
        name = base + '.' + c
        try:
            m = __import__(name, fromlist = [c])
            globs[c] = m.__getattribute__(c)
        except:
            print "Could not load %s" % name
            sys.exit(0)
