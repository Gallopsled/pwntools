# Copyright (c) 2013 Pratik Kumar Sahu, Nagendra Chowdary, Anish Mathuria
# Ported to Python by Gallopsled
import random

from pwnlib.context import context
from . import builder
from pwnlib.encoders.encoder import Encoder


class ArmEncoder(Encoder):
    """Encode ARM shellcode with an alphanumeric self-decoder.

    The encoded body is alphanumeric, but the decoder has fixed non-ASCII
    branch bytes.  The encoder therefore does not advertise a strict
    alphanumeric output constraint.

        >>> context.clear(arch='arm')
        >>> encoded = pwnlib.encoders.arm.alphanumeric.encode(b'ABCD', b'')
        >>> b'\\xf4\\xff\\xffK' in encoded
        True
        >>> b'\\xc3\\xb4' not in encoded
        True
        >>> shellcode = asm(shellcraft.sh())
        >>> encoded = pwnlib.encoders.arm.alphanumeric.encode(shellcode, b'')
        >>> process = run_shellcode(encoded)
        >>> process.sendline(b'echo hello; exit')
        >>> process.recvline()
        b'hello\\n'
    """

    arch = 'arm'
    architectures = frozenset(('arm',))
    priority = 90
    unavoidable_bytes = frozenset((0xf4, 0xff))
    supported_constraints = frozenset()
    is_deterministic = True

    blacklist: set[str] = set()
    icache_flush = 1

    def __call__(self, input, avoid, pcreg=None):
        # If randomization is disabled, ensure that the seed
        # is always the same for the builder.
        state = random.getstate()
        if not context.randomize:
            random.seed(1)

        try:
            b = builder.builder()

            enc_data = b.enc_data_builder(input)
            dec_loop = b.DecoderLoopBuilder(self.icache_flush)
            enc_dec_loop = b.encDecoderLoopBuilder(dec_loop)
            dec = b.DecoderBuilder(dec_loop, self.icache_flush)

            output, dec = b.buildInit(dec)

            output += dec
            output += enc_dec_loop
            output += enc_data

        finally:
            random.setstate(state)

        return output.encode('latin-1')


class ThumbEncoder(ArmEncoder):
    """Encode Thumb shellcode through the ARM alphanumeric decoder.

        >>> pwnlib.encoders.arm.alphanumeric.ThumbEncoder.architectures
        frozenset({'thumb'})
        >>> arm_required = pwnlib.encoders.arm.alphanumeric.ArmEncoder.unavoidable_bytes
        >>> thumb_required = pwnlib.encoders.arm.alphanumeric.ThumbEncoder.unavoidable_bytes
        >>> thumb_required > arm_required
        True
    """

    arch = 'thumb'
    architectures = frozenset(('thumb',))

    to_thumb = b'\x01\x30\x8f\xe2\x13\xff\x2f\xe1'
    unavoidable_bytes = ArmEncoder.unavoidable_bytes | frozenset(to_thumb)

    def __call__(self, input, avoid, pcreg=None):
        return super(ThumbEncoder, self).__call__(self.to_thumb + input, avoid, pcreg)


encode = ArmEncoder()
ThumbEncoder()
