# -*- coding:utf-8 -*-
"""
Encode shellcode to avoid input filtering and impress your friends!

Note
----

Some of these methods will fail on various architectures.
Your best bet is to use :func:`.encoder.encode` with an ``avoid=...``.
"""
from __future__ import absolute_import

from pwnlib.encoders import amd64
from pwnlib.encoders import arm
from pwnlib.encoders import i386
from pwnlib.encoders import mips
from pwnlib.encoders.encoder import alphanumeric
from pwnlib.encoders.encoder import encode
from pwnlib.encoders.encoder import line
from pwnlib.encoders.encoder import null
from pwnlib.encoders.encoder import printable
from pwnlib.encoders.encoder import scramble
