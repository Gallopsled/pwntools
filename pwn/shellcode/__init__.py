from io import *
from misc import *
from network import *
from nops import nops, nop_pad
from scramble import scramble
import os

module_type = os.__class__
for k, v in globals().items():
    if isinstance(v, module_type):
        if not v.__name__.startswith('pwn.'):
            del globals()[k]
    elif k.startswith('_') and not k.startswith('__'):
        del globals()[k]
del k, v, module_type
