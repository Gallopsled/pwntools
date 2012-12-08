import pwn, tempfile, subprocess, errno, os
import pwn.shellcode_helper as H

def _nowai(arch, os):
    pwn.die('I do not know how to assemble arch=' + str(arch) + ', os=' + str(os))

def _nasm(target_arch, target_os, blocks, emit_asm):
    nasminclude = os.path.join(pwn.installpath, pwn.INCLUDE, 'nasm', '')
    def cmd(src):
        cmd = ['nasm']
        if pwn.DEBUG:
            cmd += ['-D', 'DEBUG']
        cmd += ['-I', nasminclude, '-o', '/dev/stdout', src]
        return cmd

    code = ['%include "macros/macros.asm"']

    if target_arch == 'i386':
        code.append('bits 32')
        
        if target_os == 'linux':
            code.append('%include "linux/32.asm"')
        else:
            # TODO: Add FreeBSD and others
            _nowai(target_arch, target_os)
    else:
        # TODO: Add 64-bit
        _nowai(target_arch, target_os)

    for b in blocks.blocks:
        if isinstance(b, H.AssemblerText):
            code.append(b.text)
        elif isinstance(b, H.AssemblerBlob):
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
                pwn.die('nasm is not installed')
            else:
                raise

        ret = p.wait()
        if ret != 0:
            err = p.stderr.read()
            pwn.die('nasm could not compile file:\n' + err)
        return p.stdout.read()

def _asm_real(arch, os, blocks, emit_asm):
    if arch == 'i386':
        return _nasm(arch, os, blocks, emit_asm)
    _nowai(arch, os)

def asm(*blocks, **kwargs):
    blocks = H.AssemblerContainer(*blocks, os=kwargs.get('os'), arch=kwargs.get('arch'))
    emit_asm = kwargs.get('emit_asm', False)

    if all(isinstance(b, H.AssemblerBlob) for b in blocks.blocks):
        data = pwn.flat(b.blob for b in blocks.blocks)
        if emit_asm:
            return 'The following blob was computed:\n' + data.encode('hex')
        else:
            return data

    system = pwn.with_context(os = blocks.os, arch = blocks.arch)
    return _asm_real(system['arch'], system['os'], blocks, emit_asm)
