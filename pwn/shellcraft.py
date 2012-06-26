import pwn, subprocess, os, sys, warnings

INCLUDE = os.path.join(os.path.dirname(__file__), pwn.INCLUDE)
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

        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        ret = p.wait()
        if ret <> 0:
            err = p.stderr.read()
            sys.stdout.write(err)
            exit(0)
        os.unlink(src)
        return p.stdout.read()
    return assemble

# def load_codez(name):
#     path = os.path.join(os.path.dirname(__file__),
#                         name.split('.', 1)[1].replace('.', '/'))
#     mod = sys.modules[name]
#     for dir, _, files in os.walk(path):
#         try:
#             files.remove('__init__.py')
#         except ValueError:
#             pass
#         files = filter(lambda x: x.endswith('.py'), files)
#         for f in files:
#             c = f[:-3]
#             m = __
#     print name, path
#     # dir = os.path.dirname(path)
#     # for
