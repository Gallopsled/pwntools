# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division

import collections

from pwnlib.util.misc import byteset

class Encoder(object):
    _encoders = collections.defaultdict(lambda: [])

    #: Architecture which this encoder works on
    arch = None

    #: Blacklist of bytes which are known not to be supported
    blacklist = byteset()

    def __init__(self):
        """Shellcode encoder class

        Implements an architecture-specific shellcode encoder
        """
        Encoder._encoders[self.arch].append(self)

    def __call__(self, raw_bytes, avoid, pcreg):
        """avoid(raw_bytes, avoid)

        Arguments:
            raw_bytes(bytes):
                Bytes to encode
            avoid(bytes):
                Bytes to avoid
            pcreg(str):
                Register which contains the address of the shellcode.
                May be necessary for some shellcode.
        """
        raise NotImplementedError()
