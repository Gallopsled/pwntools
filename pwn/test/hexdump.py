from pwn import *
import os

data = os.urandom(50) + '\x00' * 100 + os.urandom(50) + '\x42' * 56
print hexdump(data)
