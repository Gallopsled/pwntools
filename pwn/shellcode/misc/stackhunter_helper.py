from pwn.internal.shellcode_helper import *

@shellcode_reqs(arch='i386')
def stackhunter_helper(cookie = 0x7afceb58):
    """Args: shellcode [cookie = 0x7afceb58]
    The helper for the stackhunter, which prepends the cookie
    at different alignments jump suitable jumps
"""

    cookie = int(cookie)

    return"""
stackhunter_helper:
    dd 0x%08x
    jmp short stackhunter_helper_end

    dd 0x%08x
    jmp short stackhunter_helper_end
    db 0xff
    dd 0x%08x
    jmp short stackhunter_helper_end

    dd 0x%08x
stackhunter_helper_end:
""" % (cookie, cookie, cookie, cookie)
