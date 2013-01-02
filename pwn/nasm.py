import pwn, tempfile, subprocess, errno, os
import pwn.internal.shellcode_helper as H

def _cmd(src, optimize = 'x'):
    cmd = ['nasm']
    if pwn.DEBUG:
        cmd += ['-D', 'DEBUG']
    nasminclude = os.path.join(pwn.installpath, pwn.INCLUDE, 'nasm', '')
    cmd += ['-I', nasminclude, '-O' + optimize, '-o', '/dev/stdout', src]
    return cmd

@pwn.memoize
def nasm_raw(code, checked = True, return_none = False, optimize = 'x'):

    with tempfile.NamedTemporaryFile(delete = False, prefix='pwn', suffix='.asm') as tmp:
        tmp.write(code)
        tmp.flush()

        try:
            p = subprocess.Popen(_cmd(tmp.name, optimize), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except OSError, e:
            if e.errno == errno.ENOENT:
                pwn.die('nasm is not installed')
            else:
                raise

        ret = p.wait()
        if ret != 0:
            err = p.stderr.read()
            if return_none:
                return None
            elif checked:
                pwn.die('nasm could not compile file:\n' + err)
            else:
                raise Exception('nasm could not compile file:\n' + err)
        return p.stdout.read()

def nasm(target_arch, target_os, blocks, emit_asm, checked = True):

    if target_arch != 'i386' or target_os not in ['linux', 'freebsd']:
        pwn.die('I do not know how to assemble arch=' + str(arch) + ', os=' + str(os))

    code = []

    if target_arch == 'i386':
        code.append('bits 32')

    code.append('%include "macros/macros.asm"')

    if target_os == 'linux':
        code.append('%include "linux/32.asm"')
    elif target_os == 'freebsd':
        code.append('%include "freebsd/32.asm"')

    for n, b in enumerate(blocks.blocks):
        code.append('pwn_block%d:' % n)
        if isinstance(b, H.AssemblerText):
            code.append(b.text)
        elif isinstance(b, H.AssemblerBlob):
            code.append('db ' + ', '.join('0x%02x' % ord(c) for c in b.blob))
        else:
            die("Trying to assemble something that is not an assembler block")

    code = '\n'.join(code)

    if emit_asm:
        return \
            ';;; Assemble with:\n;;;  %s\n' % \
            ' '.join(_cmd('<file>')) + code
    else:
        return nasm_raw(code, checked)
