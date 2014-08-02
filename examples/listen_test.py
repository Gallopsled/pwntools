from pwn import *

cs = [listen(1337) for _ in range(3)]

cs[0] << cs[1] << cs[2] << cs[0]

cs[0].wait()
