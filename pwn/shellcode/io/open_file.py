from pwn.internal.shellcode_helper import *

@shellcode_reqs(arch='i386', os='linux')
def open_file(filepath, flags = 0, mode = 0):
    """Args: filepath [flags = O_RDONLY] [mode = 0]
    Opens a file or directory with the specified flags and mode.
    Mode is ignored if (flags & O_CREAT) == 0
    Leaves the file descriptor in eax."""

    out = ''

    flags = arg_fixup(flags)
    mode = arg_fixup(mode)

    if flags == 0:
        out += """
            ; Clear eax, ecx, edx
            xor ecx, ecx
            imul ecx
            push eax
            mov al, SYS_open"""
    else:
        out += """
            setfd ecx, %d
            push SYS_open
            pop eax
            push eax
            inc esp""" % flags

    if (flags & 0o100) != 0:
        out += """
            setfd edx, %d""" % mode

    out += """
            %%define str `%s`
            pushstr str
            mov ebx, esp
            int 0x80
""" % filepath

    return out
