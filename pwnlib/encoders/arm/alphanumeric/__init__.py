from __future__ import absolute_import
from __future__ import division

import binascii
import random
import string
import sys

from pwnlib.context import context
from . import builder
from pwnlib.encoders.encoder import Encoder


class ArmEncoder(Encoder):
    arch = 'arm'

    blacklist  = {chr(c) for c in range(256) if chr(c) in (string.ascii_letters + string.digits)}
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

        return output.encode()

class ThumbEncoder(ArmEncoder):
    arch = 'thumb'

    to_thumb = b'\x01\x30\x8f\xe2\x13\xff\x2f\xe1'

    def __call__(self, input, avoid, pcreg=None):
        return super(ThumbEncoder, self).__call__(self.to_thumb + input, avoid, pcreg)

encode = ArmEncoder()
ThumbEncoder()
