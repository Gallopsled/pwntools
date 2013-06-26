from pwn.internal.shellcode_helper import *
from ..misc.pushstr import pushstr

@shellcode_reqs(arch=['i386', 'amd64', 'arm'], os=['linux', 'freebsd'])
def open_file(filepath, flags = 0, mode = 0, arch = None, os = None):
    """Args: filepath [flags = O_RDONLY] [mode = 0]
    Opens a file or directory with the specified flags and mode.
    Mode is ignored if (flags & O_CREAT) == 0
    Leaves the file descriptor in eax."""

    flags = arg_fixup(flags)
    mode = arg_fixup(mode)

    if arch == 'i386':
        if os == 'linux':
            return pushstr(filepath), _open_file_linux_i386(flags, mode)
        elif os == 'freebsd':
            return pushstr(filepath), _open_file_freebsd_i386(flags, mode)
    elif arch == 'amd64':
        if os in ['linux', 'freebsd']:
            return pushstr(filepath), _open_file_amd64(flags, mode)
    elif arch == 'arm' and os == 'linux':
        return _open_file_linux_arm(filepath, flags, mode)

    bug("OS/arch combination (%s, %s) is not supported for open_file" % (os, arch))

def _open_file_linux_i386(flags, mode):
    out = ''

    out += """
    mov ebx, esp
    """ + pwn.shellcode.mov('ecx', flags, raw = True) + """
    push SYS_open
    pop eax"""

    if (flags & 0o100) != 0:
        out += """
    """ + pwn.shellcode.mov('edx', mode, raw = True)

    out += '\n    int 0x80'

    return out

def _open_file_freebsd_i386(flags, mode):
    out = ['mov ecx, esp']

    if (flags & 0o100) != 0:
        out += [pushstr(p32(mode), null=False, raw=True)]

    out += [pushstr(p32(flags), null=False, raw=True)]
    out += ['push ecx']
    out += ['push SYS_open']
    out += ['pop eax']
    out += ['push eax']
    out += ['int 0x80']

    return '\n'.join('    ' + s for s in out)

def _open_file_amd64(flags, mode):
    out = ''

    out += """
            mov rdi, rsp
            push SYS_open
            pop rax
            """ + pwn.shellcode.mov('esi', flags, raw = True)

    if (flags & 0o100) != 0:
        out += """
            """ + pwn.shellcode.mov('edx', mode, raw = True)

    out += """
            syscall"""

    return out

def _open_file_linux_arm(filepath, flags, mode):
    out = []

    if (flags & 0o100) != 0:
        out += ['mov r2, #%d' % mode]


    out += ['mov r1, #%d' % flags,
            'adr r0, filepath',
            'svc SYS_open',
            'b after_open',
            'filepath: .byte %s // %s' % (', '.join(hex(ord(c)) for c in filepath + '\x00'), filepath),
            '.align 2',
            'after_open:']

    return '\n'.join(out)
