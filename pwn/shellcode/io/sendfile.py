from pwn.internal.shellcode_helper import *

@shellcode_reqs(arch='i386', os='linux')
def sendfile(in_fd = 0, out_fd = 1):
    """Args: [in_fd (imm/reg) = STD_IN, [out_fd (imm/reg) = STD_OUT]

    Calls the sendfile syscall with the given arguments.
    """

    return """
        setfd ecx, %s ; in_fd
        setfd ebx, %s ; out_fd
        push SYS_sendfile
        pop eax
        cdq ; offset
        mov esi, 0x7fffffff
        int 0x80
""" % (in_fd, out_fd)
