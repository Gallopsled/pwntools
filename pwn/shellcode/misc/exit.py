from pwn.internal.shellcode_helper import *

@shellcode_reqs(arch='i386', os=['linux', 'freebsd'])
def exit(returncode = None, os = None):
    """Exits. Default return code, None, means "I don't care"."""
    if returncode == None:
        return """
            push byte SYS_exit
            pop eax
            int 0x80
            """

    if os == 'linux':
        return """
            setfd ebx, %s
            push byte SYS_exit
            pop eax
            int 0x80""" % str(returncode)
    elif os == 'freebsd':
        if str(returncode) == "0":
            return """
                push byte SYS_exit
                pop eax
                cdq
                push edx
                push edx
                int 0x80"""
        else:
            return """
                push %s
                push byte SYS_exit
                pop eax
                push eax
                int 0x80""" % str(returncode)
    else:
        bug('OS was neither linux nor freebsd')
