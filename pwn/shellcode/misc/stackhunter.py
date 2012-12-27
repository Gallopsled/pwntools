from pwn.internal.shellcode_helper import *

@shellcode_reqs(arch='i386')
def stackhunter(cookie = 0x7afceb58):
    """Args: [cookie = 0x7afceb58]
    Returns an an egghunter, which searches from esp and upwards
    for a cookie. However to save bytes, it only looks at a single
    4-byte alignment. Use the function stackhunter_helper to
    generate a suitable cookie prefix for you.

    The default cookie has been chosen, because it makes it possible
    to shave a single byte, but other cookies can be used too.
"""

    cookie = int(cookie)

    if (cookie & 0xffffff) == 0xfceb58:
        return """
stackhunter:
        cmp dword eax, 0x%08x
        jne stackhunter+1
        jmp esp
""" % cookie

    else:
        return """
stackhunter:
    pop eax
    cmp dword eax, 0x%08x
    jne stackhunter
    jmp esp
""" % cookie
