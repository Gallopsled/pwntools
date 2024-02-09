from __future__ import absolute_import
from pwnlib.data.elf import fmtstr
from pwnlib.data.elf import relro
from pwnlib.data.elf import ret2dlresolve

import os
path = os.path.dirname(__file__)

def get(x):
    return os.path.join(path, x)
