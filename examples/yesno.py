"""
Example showing `pwnlib.ui.yesno()`
"""

from pwn import *

if ui.yesno('Do you like Pwntools?'):
    print(':D')
else:
    print(':(')
