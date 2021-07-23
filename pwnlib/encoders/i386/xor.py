# Source:
# http://www.iodigitalsec.com/python-cascading-xor-polymorphic-shellcode-generator/
#
# License:
#; Title Python XOR Shellcode Encoder
#; Author npn <npn at iodigitalsec dot com>
#; License http://creativecommons.org/licenses/by-sa/3.0/
#; Legitimate use and research only
#; This program is distributed in the hope that it will be useful,
#; but WITHOUT ANY WARRANTY; without even the implied warranty of
#; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
from __future__ import absolute_import
from __future__ import division

from pwnlib import shellcraft
from pwnlib.asm import asm
from pwnlib.context import context
from pwnlib.encoders.encoder import Encoder
from pwnlib.util.fiddling import xor_pair
from pwnlib.util.lists import group


# Note shellcode assumes it's based at ecx

class i386XorEncoder(Encoder):
    r"""Generates an XOR decoder for i386.

    >>> context.clear(arch='i386')
    >>> shellcode = asm(shellcraft.sh())
    >>> avoid = b'/bin/sh\xcc\xcd\x80'
    >>> encoded = pwnlib.encoders.i386.xor.encode(shellcode, avoid)
    >>> assert not any(c in encoded for c in avoid)
    >>> p = run_shellcode(encoded)
    >>> p.sendline(b'echo hello; exit')
    >>> p.recvline()
    b'hello\n'
    >>> encoders.i386.xor.encode(asm(shellcraft.execve('/bin/sh')), avoid=bytearray([0x31]))
    b'\xd9\xd0\xd9t$\xf4^\xfcj\x07Y\x83\xc6\x19\x89\xf7\xad\x93\xad1\xd8\xabIu\xf7\x00\x00\x00\x00h\x01\x01\x01\x00\x00\x00\x00\x01\x814$\x00\x00\x00\x00.ri\x01\x00\x00\x00\x00h/bi\x00\x00\x00\x01n\x89\xe30\x00\x01\x00\x00\xc90\xd2j\x00\x00\x00\x00\x0bX\xcd\x80'
    """

    arch = 'i386'

    stub = None

    decoder = '''
start:
    fnop
    fnstenv [esp-0xc]
    pop esi
    cld
    %s
    /* add esi, offset */
    .byte 0x83, 0xc6, (end-start)
    mov edi, esi
loop:
    lodsd
    xchg eax, ebx
    lodsd
    xor  eax, ebx
    stosd
    dec ecx
    jnz loop
end:
'''

    blacklist = set('\x14$1I^tu\x83\x89\x93\xab\xad\xc6\xd8\xd9\xf4\xf7\xfc')

    def __call__(self, raw_bytes, avoid, pcreg=''):
        while len(raw_bytes) % context.bytes:
            raw_bytes += b'\x00'

        a, b = xor_pair(raw_bytes, avoid)

        mov_ecx = shellcraft.i386.mov('ecx', len(raw_bytes) // context.bytes)
        decoder = self.decoder % mov_ecx
        decoder = asm(decoder)

        for left, right in zip(group(context.bytes, a), group(context.bytes, b)):
            decoder += left
            decoder += right

        return decoder

encode = i386XorEncoder()
