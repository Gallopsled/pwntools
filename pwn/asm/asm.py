from context import with_context
from pwn import *
import tempfile, os

class AssemblerBlock:
    pass

class AssemblerBlob(AssemblerBlock):
    def __init__(self, blob, **kwargs):
        self.arch = kwargs.get('arch')
        self.os   = kwargs.get('os')
        self.blob = blob

class AssemblerText(AssemblerBlock):
    def __init__(self, text, **kwargs):
        self.arch = kwargs.get('arch')
        self.os   = kwargs.get('os')
        self.text = text


def shellblob(f):
    def wrap(*args, **kwargs):
        blob = f(*args, **kwargs)
        return AssemblerBlob(blob, **with_context(**kwargs))
    return wrap

def shelltext(f):
    def wrap(*args, **kwargs):
        blob = f(*args, **kwargs)
        return AssemblerText(blob, **with_context(**kwargs))
    return wrap

def _nowai(arch, os):
    die('I do not know how to assemble arch=' + str(arch) + ', os=' + str(os))


_nasminclude = os.path.join(installpath, INCLUDE, 'nasm', '')
def nasm(arch, os, blocks, emit_asm):
    def cmd(src):
        cmd = ['nasm']
        if DEBUG:
            cmd += ['-D', 'DEBUG']
        cmd += ['-I', _nasminclude, '-o' ,'/dev/stdout', src]
        return cmd

    code = ['%include "macros/macros.asm"']

    if arch == 'i386':
        code.append('bits 32')
        
        if os == 'linux':
            code.append('%include "linux/32.asm"')
        else:
            # TODO: Add FreeBSD and others
            _nowai(arch, os)
    else:
        # TODO: Add 64-bit
        _nowai(arch, os)

    for b in blocks:
        if isinstance(b, AssemblerText):
            code.append(b.text)
        elif isinstance(b, AssemblerBlob):
            code.append('db ' + ' '.join('0x%02x' % ord(c) for c in b.blob))
        else:
            code.append(b)
    
    code = '\n'.join(code)

    if emit_asm:
        return \
            ';;; Assemble with:\n;;;  %s\n' % \
            ' '.join(cmd('<file>')) + code


    with tempfile.NamedTemporaryFile() as tmp:
        tmp.write(code)
        tmp.flush()

        try:
            p = subprocess.Popen(cmd(tmp.name), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except OSError, e:
            if e.errno == errno.ENOENT:
                die('nasm is not installed')
            else:
                raise

        ret = p.wait()
        if ret != 0:
            err = p.stderr.read()
            die('nasm could not compile file:\n' + err)
        return p.stdout.read()

def asm_real(arch, os, blocks, emit_asm):
    if arch == 'i386':
        return nasm(arch, os, blocks, emit_asm)
    _nowai(arch, os)

def asm(*blocks, **kwargs):
    os        = kwargs.get('os')
    arch      = kwargs.get('arch')
    emit_asm  = kwargs.get('emit_asm', False)
    all_blobs = True

    for b in blocks:
        if not isinstance(b, AssemblerBlob):
            all_blobs = False

        if isinstance(b, AssemblerBlock):
            if os   == None: os   = b.os
            if arch == None: arch = b.arch

            if os != b.os and b.os != None:
                die('Trying to assemble blocks with different os: ' + os + ' and ' + b.os)

            if arch != b.arch and b.arch != None:
                die('Trying to assemble blocks with different archs: ' + arch + ' and ' + b.arch)
        elif not isinstance(b, str):
            die('Unknown block of type ' + str(type(b)) + ':\n' + str(b))


    if all_blobs:
        data = flat(b.blob for b in blocks)
        if emit_asm:
            return 'The following blob was computed:\n' + data.encode('hex')
        else:
            return data

    system = with_context(os = os, arch = arch)
    return asm_real(system['arch'], system['os'], blocks, emit_asm)
