from pwn.internal.shellcode_helper import shellcode_reqs

@shellcode_reqs(arch = 'i386')
def trap():
    return 'int3'
