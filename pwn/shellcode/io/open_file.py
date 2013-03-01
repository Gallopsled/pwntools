from pwn.internal.shellcode_helper import *
from ..misc.pushstr import pushstr

@shellcode_reqs(arch=['i386', 'amd64'], os='linux')
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
    elif arch == 'amd64':
        if os == 'linux':
            return pushstr(filepath), _open_file_linux_amd64(flags, mode)
    bug("OS/arch combination (%s, %s) is not supported for open_file" % (os, arch))

def _open_file_linux_i386(flags, mode):
    out = ''

    out += """
    mov ebx, esp
    setfd ecx, %d
    push SYS_open
    pop eax""" % flags

    if (flags & 0o100) != 0:
        out += """
    setfd edx, %d""" % mode

    out += '\n    int 0x80'

    return out

def _open_file_linux_amd64(flags, mode):
    out = ''

    out += """
            mov rdi, rsp
            push SYS64_open
            pop rax
            setfd esi, %d
""" % flags

    if (flags & 0o100) != 0:
        out += """
            setfd ecx, %d""" % mode

    out += 'syscall'

    return out
