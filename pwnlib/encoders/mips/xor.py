# Source:
# https://github.com/zcutlip/bowcaster/blob/master/src/bowcaster/encoders/mips.py
#
# Copyright (c) 2013 Zachary Cutlip <uid000@gmail.com>,
#               2013 Tactical Network Solutions, LLC
#
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is furnished to do
# so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
from __future__ import absolute_import
from __future__ import division

import six
from pwnlib import asm
from pwnlib import shellcraft
from pwnlib.context import context
from pwnlib.encoders.encoder import Encoder
from pwnlib.util.fiddling import xor_key

decoders = {
    'little': b''.join([
    b'SIZ2SIZ1\x0e\x24',    # li t6,-5
    b'\x27\x70\xc0\x01',    # nor    t6,t6,zero
    b'\xa3\xff\x0b\x24',    # li t3,-93
    b'\x26\x40\xce\x01',    # xor    t0,t6,t6
    b'\xff\xff\x08\x21',    # addi   t0,t0,-1
    b'\xff\xff\x10\x05',    # bltzal t0,14 <next>
    b'\x82\x82\x08\x28',    # slti   t0,zero,-32126
    b'\xe2\xff\xfd\x23',    # addi   sp,ra,-30
    b'\x27\x58\x60\x01',    # nor    t3,t3,zero
    b'\x21\xc8\xeb\x03',    # addu   t9,ra,t3
    b'\x82\x82\x17\x28',    # slti   s7,zero,-32126
    b'\xfc\xff\x31\x8f',    # lw s1,-4(t9)
    b'\xfb\xff\x0c\x24',    # li t4,-5
    b'\x27\x60\x80\x01',    # nor    t4,t4,zero
    b'\xfd\xff\x8f\x21',    # addi   t7,t4,-3
    b'\xfc\xff\x28\x8f',    # lw t0,-4(t9)
    b'\x21\xb8\xef\x02',    # addu   s7,s7,t7
    b'\x26\x18\x11\x01',    # xor    v1,t0,s1
    b'\x2b\xf0\xee\x02',    # sltu   s8,s7,t6
    b'\xfc\xff\x23\xaf',    # sw v1,-4(t9)
    b'\xfa\xff\x1e\x14',    # bne    zero,s8,3c <loop>
    b'\x21\xc8\x2c\x03',    # addu   t9,t9,t4
    b'\xfd\xff\x86\x21',    # addi   a2,t4,-3
    b'\xf8\xff\xa6\xaf',    # sw a2,-8(sp)
    b'\x26\x28\xce\x01',    # xor    a1,t6,t6
    b'\xfc\xff\xa5\xaf',    # sw a1,-4(sp)
    b'\xf8\xff\xa4\x27',    # addiu  a0,sp,-8
    b'\x46\x10\x02\x24',    # li v0,4166
    b'\x0c\x54\x4a\x01'     # syscall   0x52950
    ]),
    'big': b''.join([
    b'\x24\x0eSIZ1SIZ2',    # li t6,-5
    b'\x01\xc0\x70\x27',    # nor    t6,t6,zero
    b'\x24\x0b\xff\xa3',    # li t3,-93
    b'\x01\xce\x40\x26',    # xor    t0,t6,t6
    b'\x21\x08\xff\xff',    # addi   t0,t0,-1
    b'\x05\x10\xff\xff',    # bltzal t0,14 <next>
    b'\x28\x08\x82\x82',    # slti   t0,zero,-32126
    b'\x23\xfd\xff\xe2',    # addi   sp,ra,-30
    b'\x01\x60\x58\x27',    # nor    t3,t3,zero
    b'\x03\xeb\xc8\x21',    # addu   t9,ra,t3
    b'\x28\x17\x82\x82',    # slti   s7,zero,-32126
    b'\x8f\x31\xff\xfc',    # lw s1,-4(t9)
    b'\x24\x0c\xff\xfb',    # li t4,-5
    b'\x01\x80\x60\x27',    # nor    t4,t4,zero
    b'\x21\x8f\xff\xfd',    # addi   t7,t4,-3
    b'\x8f\x28\xff\xfc',    # lw t0,-4(t9)
    b'\x02\xef\xb8\x21',    # addu   s7,s7,t7
    b'\x01\x11\x18\x26',    # xor    v1,t0,s1
    b'\x02\xee\xf0\x2b',    # sltu   s8,s7,t6
    b'\xaf\x23\xff\xfc',    # sw v1,-4(t9)
    b'\x14\x1e\xff\xfa',    # bne    zero,s8,3c <loop>
    b'\x03\x2c\xc8\x21',    # addu   t9,t9,t4
    b'\x21\x86\xff\xfd',    # addi   a2,t4,-3
    b'\xaf\xa6\xff\xf8',    # sw a2,-8(sp)
    b'\x01\xce\x28\x26',    # xor    a1,t6,t6
    b'\xaf\xa5\xff\xfc',    # sw a1,-4(sp)
    b'\x27\xa4\xff\xf8',    # addiu  a0,sp,-8
    b'\x24\x02\x10\x46',    # li v0,4166
    b'\x01\x4a\x54\x0c'    # syscall 0x52950
    ])
}



class MipsXorEncoder(Encoder):
    r"""Generates an XOR decoder for MIPS.

    >>> context.clear(arch='mips')
    >>> shellcode = asm(shellcraft.sh())
    >>> avoid = b'/bin/sh\x00'
    >>> encoded = pwnlib.encoders.mips.xor.encode(shellcode, avoid)
    >>> assert not any(c in encoded for c in avoid)
    >>> p = run_shellcode(encoded)
    >>> p.sendline(b'echo hello; exit')
    >>> p.recvline()
    b'hello\n'
    """

    arch = 'mips'
    blacklist = cannot_avoid = set(b''.join(v for v in decoders.values()))

    def __call__(self, raw_bytes, avoid, pcreg=''):

        assert 0 == len(raw_bytes) % context.bytes, "Payload is not aligned"

        size = (len(raw_bytes) // 4) + 1
        assert size < 0x10000, "Payload is too long"

        size   = size ^ 0xffff
        sizelo = size & 0xff
        sizehi = size >> 8

        decoder = decoders[context.endian]
        decoder = decoder.replace(b'SIZ1', six.int2byte(sizehi))
        decoder = decoder.replace(b'SIZ2', six.int2byte(sizelo))

        key, data = xor_key(raw_bytes, avoid=avoid)

        return decoder + key + data

encode = MipsXorEncoder()
