from pwn.internal.shellcode_helper import shellcode_reqs

@shellcode_reqs(blob = True, arch = ['i386', 'amd64'])
def trap():
    """Returns a int3 instruction for debugging."""

    # Everybody should know that this is int3!
    return '\xcc'
