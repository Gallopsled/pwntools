"""
Example showing `pwnlib.ui.options()`
"""

from pwn import *

opts = [string.ascii_letters[x] for x in range(12)]
print('You choose "%s"' % opts[options('Pick one:', opts)])
