from pwn.internal.shellcode_helper import shellcode_reqs

@shellcode_reqs(arch = ['i386', 'amd64', 'arm', 'thumb', 'mips'])
def nop(arch = None):
    """Returns a no operation instruction."""

    if arch in ['i386', 'amd64']:
        return 'nop'
    elif arch in ['arm', 'thumb']:
        return 'orr r4, r4, r4'
    elif arch in ['mips']:
        return 'or $ra, $ra, $ra'
