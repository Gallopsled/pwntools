from pwn.internal.shellcode_helper import *
from ..misc.pushstr import pushstr

@shellcode_reqs(arch=['i386', 'amd64', 'arm'], os=['linux', 'freebsd'])
def read_stack(in_fd = 0, size = 255, allocate_stack = True, arch = None, os = None):
    """Args: [in_fd (imm/reg) = STDIN_FILENO] [size = 255] [allocate_stack = True]

    Reads to the stack.

    You can optioanlly shave a few bytes not allocating the stack space.

    Leaves the size read in eax.
    """

    size = arg_fixup(size)

    if arch == 'i386':
        if os == 'linux':
            return _read_stack_linux_i386(in_fd, size, allocate_stack)
        elif os == 'freebsd':
            return _read_stack_freebsd_i386(in_fd, size, allocate_stack)
    if arch == 'amd64':
        return _read_stack_amd64(in_fd, size, allocate_stack)
    if arch == 'arm' and os == 'linux':
        return _read_stack_linux_arm(in_fd, size, allocate_stack)

    no_support('read_stack', os, arch)

def _read_stack_linux_i386(in_fd, size, allocate_stack):
    out = """
            """ + pwn.shellcode.mov('ebx', in_fd, raw = True) + """
            push SYS_read
            pop eax
            cdq
            mov dl, %s""" % size

    if allocate_stack:
        out += """
            sub esp, edx"""

    out += """
            mov ecx, esp
            int 0x80"""

    return out

def _read_stack_freebsd_i386(in_fd, size, allocate_stack):
    out = [pwn.shellcode.mov('ebp', in_fd, raw = True),
           "push SYS_read",
           "pop eax",
           pushstr(p32(size), null = False, raw = True),
           "pop ebx"]

    if allocate_stack:
        out += ["sub esp, ebx"]

    out += ["pushad",
            "pop edi",
            "int 0x80",
            "push eax",
            "popad",
            "mov eax, edi"]

    return "\n".join("    " + s for s in out)

def _read_stack_amd64(in_fd, size, allocate_stack):
    out = ['push %s' % str(in_fd),
           'pop rdi',
           'push %s' % str(size),
           'pop rdx']

    if allocate_stack:
        out += ["sub rsp, rdx"]

    out += ['mov rsi, rsp',
            'push SYS_read',
            'pop rax',
            'syscall']

    return indent_shellcode(out)

def _read_stack_linux_arm(in_fd, size, allocate_stack):
    out = []

    if allocate_stack:
        out += ['sub sp, #%d' % pwn.align(4, size)]

    out += [pwn.shellcode.mov('r0', in_fd, raw = True),
            pwn.shellcode.mov('r2', size, raw = True),
            'mov r1, sp',
            'svc SYS_read']

    return '\n'.join(out)
