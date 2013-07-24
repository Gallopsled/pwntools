from pwn.internal.shellcode_helper import shellcode_reqs

@shellcode_reqs(arch = ['i386', 'amd64', 'arm', 'thumb', 'mips'])
def infloop(arch = None):
    """Spawns an infinite loop by jumping to itself."""
    if arch in ['i386', 'amd64']:
        return 'jmp $'
    elif arch in ['arm', 'thumb', 'mips']:
        return '.infloop: b .infloop'
    else:
        bug('infloop does not support architecture "%s"' % arch)
