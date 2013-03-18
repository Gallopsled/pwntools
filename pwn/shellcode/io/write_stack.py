from pwn.internal.shellcode_helper import *
from ..misc.pushstr import pushstr

@shellcode_reqs(arch=['i386', 'amd64'], os=['linux', 'freebsd'])
def write_stack(out_fd = 1, size = 127, arch = None, os = None):
    """Args: [out_fd (imm/reg) = STD_IN] [size(imm/reg) = 255]

    Writes from the stack.
    """

    size = arg_fixup(size)

    if arch == 'i386':
        if os == 'linux':
            return _write_stack_linux_i386(out_fd, size)
        elif os == 'freebsd':
            return _write_stack_freebsd_i386(out_fd, size)
    elif arch == 'amd64':
        if os in ['linux', 'freebsd']:
            return _write_stack_amd64(out_fd, size)

    bug('OS/arch combination (%s, %s) is not supported for write_stack' % (os, arch))


def _write_stack_linux_i386(out_fd, size):

    out = """
            setfd ebx, %s""" % out_fd

    if isinstance(size, int):
        out += """
            push SYS_write
            pop eax
            cdq
            mov dl, %s""" % size
    else:
        out += """
            setfd edx, %s
            push SYS_write
            pop eax""" % size

    out += """
            mov ecx, esp
            int 0x80"""

    return out

def _write_stack_freebsd_i386(out_fd, size):
    out  = ['mov ecx, esp']

    if isinstance(size, int):
        out += [pushstr(p32(size), null=False, raw=True)]
    else:
        out += ["setfd ebx, %s" % size,
                "push ebx"]
    out += ['push ecx']
    if isinstance(out_fd, int):
        out += [pushstr(p32(out_fd), null=False, raw=True)]
    else:
        out += ["setfd ebx, %s" % out_fd,
                "push ebx"]
    out += ['push SYS_write']
    out += ['pop eax']
    out += ['push eax']
    out += ['int 0x80']

    return '\n'.join('    ' + s for s in out)


def _write_stack_amd64(out_fd, size):
    return """
        push %s
        pop rdi
        mov rsi, rsp
        push %s
        pop rdx
        push SYS64_write
        pop rax
        syscall""" % (str(out_fd), str(size))
