"""
Example showing `pwnlib.ui.options()`
"""

from pwn import *

opts = [string.letters[x] for x in range(10)]
print('You choose "%s"' % opts[options('Pick one:', opts)])
