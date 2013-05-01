from pwn.internal.shellcode_helper import shellcode_reqs

@shellcode_reqs(arch = ['i386', 'amd64', 'arm', 'thumb', 'mips'])
def trap(arch = None):
    """Returns a breakpoint instruction for debugging."""

    if arch in ['i386', 'amd64']:
        return 'int3'
    elif arch in ['arm', 'thumb']:
        return 'bkpt'
    elif arch in ['mips']:
        return 'break 2'
