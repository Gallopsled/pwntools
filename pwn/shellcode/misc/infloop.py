from pwn.internal.shellcode_helper import shellcode_reqs

@shellcode_reqs(blob = True, arch = 'i386')
def infloop():
    return '\xeb\xfe'
