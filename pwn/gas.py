import pwn

def _cmd(arch, src):
    import os.path
    cmd = ["cpp"]
    if pwn.DEBUG:
        cmd += ['-D', 'DEBUG']
    include = os.path.join(pwn.installpath, pwn.INCLUDE, 'gas', '')
    cmd += ['-I', include, src]
    cmd += ['|', os.path.join(pwn.installpath, 'binutils', arch + '-as')]
    cmd += ['-o', src + '.out']
    cmd += ['&&', os.path.join(pwn.installpath, 'binutils', 'promisc-objcopy')]
    cmd += [src + '.out', '/dev/stdout', '-j.shellcode', '-Obinary']
    return ' '.join(cmd)

@pwn.memoize
def gas_raw(arch, code, checked = True, return_none = False):
    import tempfile, subprocess, errno
    with tempfile.NamedTemporaryFile(prefix='pwn', suffix='.asm') as tmp:
        tmp.write(code)
        tmp.flush()

        try:
            p = subprocess.Popen(_cmd(arch, tmp.name), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell = True)
        except OSError, e:
            if e.errno == errno.ENOENT:
                pwn.die('gas is not installed')
            else:
                raise

        ret = p.wait()
        if ret != 0:
            err = p.stderr.read()
            if return_none:
                return None
            elif checked:
                pwn.die('gas could not compile file:\n' + err)
            else:
                raise Exception('gas could not compile file:\n' + err)
        return p.stdout.read()

def header(target_arch, target_os):
    if target_arch == 'arm':
        return ['.arm']
    elif target_arch == 'thumb':
        return ['.thumb']
    return []

def gas(target_arch, target_os, blocks, emit_asm, checked = True):
    import pwn.internal.shellcode_helper as H
    code =  ['.section .shellcode,"ax"']
    code += ['#include <%s/%s.h>' % (target_arch, target_os)]
    code += header(target_arch, target_os)

    if target_arch == 'thumb':
        target_arch = 'arm'

    for n, b in enumerate(blocks.blocks):
        code.append('pwn_block%d:' % n)
        if isinstance(b, H.AssemblerText):
            code.append(b.text)
        elif isinstance(b, H.AssemblerBlob):
            code.append('.byte ' + ', '.join('0x%02x' % ord(c) for c in b.blob))
        else:
            pwn.die("Trying to assemble something that is not an assembler block")

    code = '\n'.join(code)

    if emit_asm:
        return \
            ';;; Assemble with:\n;;;  %s\n' % \
            _cmd(target_arch, '<file>') + code
    else:
        return gas_raw(target_arch, code, checked)
