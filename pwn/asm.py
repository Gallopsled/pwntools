from context import with_context, possible_contexts, ExtraContext, validate_context
from pwn import die, concat_all, installpath, INCLUDE, DEBUG, kwargs_remover, ewraps
import tempfile, subprocess
import os as OS

all_shellcodes = {}

class AssemblerBlock:
    def __add__(self, other):
        return AssemblerContainer(self, other)

    def __radd__(self, other):
        return AssemblerContainer(other, self)

    def __eq__(self, other):
        return self.__dict__ == other.__dict__

class AssemblerBlob(AssemblerBlock):
    def __init__(self, blob, **kwargs):
        self.arch = kwargs.get('arch')
        self.os   = kwargs.get('os')
        self.blob = blob

        if not isinstance(blob, str):
            die('Trying to create an AssemblerBlob class, but the blob does not have type str.\nThe type is ' + str(type(blob)) + ' with the value:\n' + repr(blob)[:100])

class AssemblerText(AssemblerBlock):
    def __init__(self, text, **kwargs):
        self.arch = kwargs.get('arch')
        self.os   = kwargs.get('os')
        self.text = text

        if not isinstance(text, str):
            die('Trying to create an AssemblerText class, but the text does not have type str.\nThe type is ' + str(type(text)) + ' with the value:\n' + repr(text)[:100])

class AssemblerContainer(AssemblerBlock):
    def __init__(self, *blocks, **kwargs):
        self.arch   = kwargs.get('arch')
        self.os     = kwargs.get('os')
        self.blocks = []
        
        for b in concat_all(list(blocks)):
            if isinstance(b, AssemblerBlock):
                if self.os   == None: self.os   = b.os
                if self.arch == None: self.arch = b.arch

                if self.os != b.os and b.os != None:
                    die('Trying to combine assembler blocks with different os: ' + self.os + ' and ' + b.os)

                if self.arch != b.arch and b.arch != None:
                    die('Trying to combine assembler blocks with different archs: ' + self.arch + ' and ' + b.arch)

            if isinstance(b, AssemblerContainer):
                self.blocks.extend(b.blocks)
            elif isinstance(b, str) or isinstance(b, AssemblerBlock):
                self.blocks.append(b)
            else:
                die('Trying to force something of type ' + str(type(b)) + ' into an assembler block. Its value is:\n' + repr(b)[:100])

def _nowai(arch, os):
    die('I do not know how to assemble arch=' + str(arch) + ', os=' + str(os))

def _nasm(arch, os, blocks, emit_asm):
    nasminclude = OS.path.join(installpath, INCLUDE, 'nasm', '')
    def cmd(src):
        cmd = ['nasm']
        if DEBUG:
            cmd += ['-D', 'DEBUG']
        cmd += ['-I', nasminclude, '-o', '/dev/stdout', src]
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

    for b in blocks.blocks:
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

def _asm_real(arch, os, blocks, emit_asm):
    if arch == 'i386':
        return _nasm(arch, os, blocks, emit_asm)
    _nowai(arch, os)

def asm(*blocks, **kwargs):
    blocks = AssemblerContainer(*blocks, os=kwargs.get('os'), arch=kwargs.get('arch'))

    if all(isinstance(b, AssemblerBlob) for b in blocks.blocks):
        data = flat(b.blob for b in blocks.blocks)
        if emit_asm:
            return 'The following blob was computed:\n' + data.encode('hex')
        else:
            return data

    system = with_context(os = blocks.os, arch = blocks.arch)
    return _asm_real(system['arch'], system['os'], blocks, kwargs.get('emit_asm', False))

def shellcode_wrapper(f, args, kwargs):
    kwargs = with_context(**kwargs)
    return f(*args, **kwargs_remover(f, kwargs, possible_contexts.keys()))

def shellcode_reqs(**supported_context):
    '''A decorator for shellcode functions, which registers the function
    with shellcraft and validates the context when the function is called.
    
    Example usage:
    @shellcode_reqs(os = ['linux', 'freebsd'], arch = 'i386')
    def sh(os = None):
        ...

    Notice that in this example the decorator will guarantee that os is
    either 'linux' or 'freebsd' before sh is called.
    '''

    for k,vs in supported_context.items():
        if not isinstance(vs, list):
            vs = supported_context[k] = [vs]
        for v in vs:
            validate_context(k, v)

    def deco(f):
        all_shellcodes[f.func_name] = (f, supported_context)
        @ewraps(f)
        def wrapper(*args, **kwargs):
            with ExtraContext(kwargs) as kwargs:
                for k,vs in supported_context.items():
                    if kwargs[k] not in vs:
                        die('Invalid context for ' + f.func_name + ': ' + k + '=' + str(kwargs[k]) + ' is not supported')
                r = shellcode_wrapper(f, args, kwargs)
                if isinstance(r, AssemblerBlock):
                    return r
                return AssemblerText(r, **kwargs)
        return wrapper
    return deco

