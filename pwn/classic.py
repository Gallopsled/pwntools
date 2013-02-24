from pwn import *
from pwn.shellcode import *
context('i386', 'linux', 'ipv4')

log.warning("Consider switching to using context('i386', 'linux', 'ipv4') instead")
