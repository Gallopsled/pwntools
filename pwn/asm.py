import pwn, tempfile, subprocess, errno, os
import pwn.internal.shellcode_helper as H

def _asm_real(arch, os, blocks, emit_asm, checked = True):
    if arch in ['i386', 'amd64'] and os in ['linux', 'freebsd']:
        return pwn.nasm.nasm(arch, os, blocks, emit_asm, checked)
    pwn.die('I do not know how to assemble arch=' + str(arch) + ', os=' + str(os))

def asm(*blocks, **kwargs):
    blocks = H.AssemblerContainer(*blocks, os=kwargs.get('os'), arch=kwargs.get('arch'), cast = 'text')
    emit_asm = kwargs.get('emit_asm', False)

    if all(isinstance(b, H.AssemblerBlob) for b in blocks.blocks):
        data = pwn.flat(b.blob for b in blocks.blocks)
        if emit_asm:
            return 'The following blob was computed:\n' + data.encode('hex')
        else:
            return data

    system = pwn.with_context(os = blocks.os, arch = blocks.arch)
    return _asm_real(system['arch'], system['os'], blocks, emit_asm, kwargs.get('checked', True))
