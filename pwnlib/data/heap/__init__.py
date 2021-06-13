from __future__ import absolute_import
from pwnlib.data.heap import x86_64

import os
path = os.path.dirname(__file__)

def get(x):
    return os.path.join(path, x)