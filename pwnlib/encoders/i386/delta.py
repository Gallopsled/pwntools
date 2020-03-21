from __future__ import absolute_import
from __future__ import division

import six
import collections
from random import choice
from random import randint

from pwnlib.asm import asm
from pwnlib.asm import disasm
from pwnlib.context import context
from pwnlib.encoders.encoder import Encoder
from pwnlib.util.fiddling import hexdump


'''
base:
    fnop
    cld
    fnstenv     [esp - 0xc]
    pop         esi
    /* add esi, data - base */
    .byte 0x83, 0xc6, data - base
    mov edi, esi
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

class i386DeltaEncoder(Encoder):
    r"""
    i386 encoder built on delta-encoding.

    In addition to the loader stub, doubles the size of the shellcode.

    Example:

        >>> sc = pwnlib.encoders.i386.delta.encode(b'\xcc', b'\x00\xcc')
        >>> e  = ELF.from_bytes(sc)
        >>> e.process().poll(True)
        -5
    """

    arch       = 'i386'
    stub       = None
    terminator = 0xac
    raw        = b'\xd9\xd0\xfc\xd9t$\xf4^\x83\xc6\x18\x89\xf7\xac\x93\xac(\xd8\xaa\x80\xeb\xacu\xf5'

    blacklist  = set(raw)

    def __call__(self, raw_bytes, avoid, pcreg=''):
        table = collections.defaultdict(lambda: [])
        endchar = bytearray()

        not_bad = lambda x: six.int2byte(x) not in avoid
        not_bad_or_term = lambda x: not_bad(x) and x != self.terminator

        for i in filter(not_bad_or_term, range(0, 256)):
            endchar.append(i)
            for j in filter(not_bad, range(0, 256)):
                table[(j - i) & 0xff].append(bytearray([i, j]))

        res = bytearray(self.raw)

        for c in bytearray(raw_bytes):
            l = len(table[c])
            if l == 0:
                print('No encodings for character %02x' % c)
                return None

            res += table[c][randint(0, l - 1)]

        res.append(self.terminator)
        res.append(choice(endchar))

        return bytes(res)

encode = i386DeltaEncoder()
