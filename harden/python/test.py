from pwn import *
context('i386', 'linux')
import amnesia

if raw_input() == 'foo':
    print text.redbg("AINT GONNA HAPPEN")
else:
    print repr(asm('xor ecx, ecx'))
#print open('whitelist').read()
