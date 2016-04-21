# -*- coding:utf-8 -*-
"""
Encode shellcode to avoid input filtering and impress your friends!
"""
from . import amd64
from . import arm
from . import i386
from . import mips
from .encoder import Encoder
from .encoder import alphanumeric
from .encoder import encode
from .encoder import line
from .encoder import null
from .encoder import printable
from .encoder import scramble
