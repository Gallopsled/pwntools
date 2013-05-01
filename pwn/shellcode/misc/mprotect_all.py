from pwn.internal.shellcode_helper import *

@shellcode_reqs(arch='i386', os='linux')
def mprotect_all(clear_ebx = True, fix_null = False):
    """Args: [clear_ebx = True] [fix_null = False]
    Calls mprotect(page, 4096, PROT_READ | PROT_WRITE | PROT_EXEC)
    for every page.

    The exception is, for the first call (the null page),
    the length has not been initialized, which means that the
    call is mprotect(0, ecx, PROT_READ | PROT_WRITE | PROT_EXEC).
    If you really need the null page, set fix_null to True.

    It takes around 0.3 seconds on my box, but your milage may vary."""
    clears = ''

    if clear_ebx:
        clears += 'xor ebx, ebx\n'
    if fix_null:
        clears += 'xor ecx, ecx\n'
    return """
mprotect_all:
        %s
.loop:
    push PROT_READ | PROT_WRITE | PROT_EXEC
    pop edx
    push SYS_mprotect
    pop eax
    int 0x80
    xor ecx, ecx
    mov ch, 0x10
    add ebx, ecx
    jnz .loop
""" % clears
