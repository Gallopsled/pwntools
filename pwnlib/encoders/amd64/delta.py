from ..i386.delta import i386DeltaEncoder


class amd64DeltaEncoder(i386DeltaEncoder):
    """
    amd64 encoder built on delta-encoding.

    In addition to the loader stub, doubles the size of the shellcode.

    >>> context.clear(arch='amd64')
    >>> shellcode = asm(shellcraft.sh())
    >>> avoid = '/bin/sh\x00'
    >>> encoded = pwnlib.encoders.amd64.delta.encode(shellcode, avoid)
    >>> assert not any(c in encoded for c in avoid)
    >>> p = run_shellcode(encoded)
    >>> p.sendline('echo hello; exit')
    >>> p.recvline()
    """
    assembly = '''
base:
    lea         rsi, base[rip]
    /* add rsi, (data-base) */
    .byte 0x48, 0x83, 0xc6, (data - base)
    cld
    mov         rdi, rsi

next:
    lodsb
    xchg        eax, ebx
    lodsb
    sub         al, bl
    stosb
    sub         bl, 0xac
    jnz         next

data:
'''
    arch      = 'amd64'
    raw       = 'H\x8d5\xf9\xff\xff\xffH\x83\xc6\x1a\xfcH\x89\xf7\xac\x93\xac(\xd8\xaa\x80\xeb\xacu\xf5'
    blacklist = set(raw)

encode = amd64DeltaEncoder()
__all__ = [encode]
