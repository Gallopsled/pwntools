"""
Example showing `pwnlib.ui.yesno()`
"""
from __future__ import print_function

from pwn import *

if ui.yesno('Do you like Pwntools?'):
    print(':D')
else:
    print(':(')
