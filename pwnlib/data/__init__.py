from __future__ import absolute_import

try:
    # These files are not distributed with Pwntools, but
    # are in the source tree and used for testing.
    from pwnlib.data import elf
except ImportError:
    pass

import os
path = os.path.dirname(__file__)

