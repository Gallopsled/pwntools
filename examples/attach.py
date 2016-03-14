"""
Example showing `pwnlib.gdb.attach()`
"""

from pwn import *

bash = process('/bin/bash')
gdb.attach(bash, execute = '''
p "hello from pwnlib"
c
''')
bash.interactive()
