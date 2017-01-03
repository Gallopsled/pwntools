from __future__ import absolute_import

from pwnlib import shellcraft
from pwnlib.asm import asm
from pwnlib.context import context
from pwnlib.encoders.encoder import Encoder
from pwnlib.util.fiddling import xor_key
from pwnlib.util.lists import group
from pwnlib.util.packing import u8


class ArmXorEncoder(Encoder):
    r"""Generates an XOR decoder for ARM.

    >>> context.clear(arch='arm')
    >>> shellcode = asm(shellcraft.sh())
    >>> avoid = 'binsh\x00\n'
    >>> encoded = pwnlib.encoders.arm.xor.encode(shellcode, avoid)
    >>> assert not any(c in encoded for c in avoid)
    >>> p = run_shellcode(encoded)
    >>> p.sendline('echo hello; exit')
    >>> p.recvline()
    'hello\n'
    """

    arch = 'arm'

    decoder = """
    adr r8, payload
    mov r4, #%(length)s
    adr r6, xor_cacheflush
loop:
    cmp  r4, #%(maximum)s
    bxhi r6
    sub  r4, r4, #%(length)s
    ldrb r5, [r8, r4]
    eor  r5, r5, #%(key)s
    strb r5, [r8, r4]
    add  r4, r4, #%(length)s + 1
    b loop

xor_cacheflush:
    %(cacheflush)s
payload:
    """

    blacklist = set("\x01\x80\x03\x85\x04\x07\x87\x0c\x8f\x0f\x16\x1c\x9f\x84\xa0%$'-/\xb0\xbd\x81A@\xc2DG\xc6\xc8OPT\xd8_\xe1`\xe3\xe2\xe5\xe7\xe9\xe8\xea\xe0p\xf7")

    def __call__(self, raw_bytes, avoid, pcreg=''):
        key, xordata = xor_key(raw_bytes, avoid, size=1)
        key          = u8(key)
        maximum      = 256
        length       = len(raw_bytes)
        cacheflush   = shellcraft.arm.linux.cacheflush()
        decoder      = asm(self.decoder % locals())
        return decoder + xordata

encode = ArmXorEncoder()
