import pwn

def _cmd(src, optimize = 'x'):
    import os.path
    cmd = ['nasm']
    if pwn.DEBUG:
        cmd += ['-D', 'DEBUG']
    nasminclude = os.path.join(pwn.installpath, pwn.INCLUDE, 'nasm', '')
    cmd += ['-I', nasminclude, '-O' + optimize, '-o', '/dev/stdout', src]
    return cmd

@pwn.memoize
def nasm_raw(code, checked = True, return_none = False, optimize = 'x'):
    import tempfile, subprocess, errno
    with tempfile.NamedTemporaryFile(prefix='pwn', suffix='.asm') as tmp:
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
    import pwn.internal.shellcode_helper as H

    if target_arch not in ['i386', 'amd64'] or target_os not in ['linux', 'freebsd']:
        pwn.die('I do not know how to assemble arch=' + str(target_arch) + ', os=' + str(target_os))

    code = []

    if target_arch == 'i386':
        code.append('bits 32')
    elif target_arch == 'amd64':
        code.append('bits 64')

    code.append('%include "macros/macros.asm"')

    if target_arch == 'i386':
        if target_os == 'linux':
            code.append('%include "linux/32.asm"')
        elif target_os == 'freebsd':
            code.append('%include "freebsd/32.asm"')
    elif target_arch == 'amd64':
        if target_os == 'linux':
            code.append('%include "linux/64.asm"')
        elif target_os == 'freebsd':
            code.append('%include "freebsd/64.asm"')


    for n, b in enumerate(blocks.blocks):
        code.append('pwn_block%d:' % n)
        if isinstance(b, H.AssemblerText):
            code.append(b.text)
        elif isinstance(b, H.AssemblerBlob):
            code.append('db ' + ', '.join('0x%02x' % ord(c) for c in b.blob))
        else:
            pwn.die("Trying to assemble something that is not an assembler block")

    code = '\n'.join(code)

    if emit_asm:
        return \
            ';;; Assemble with:\n;;;  %s\n' % \
            ' '.join(_cmd('<file>')) + code
    else:
        return nasm_raw(code, checked)
