import sys, struct, os

BASE = 0x100000

def p(n):
    return sys.stdout.write(struct.pack('I', n))

tot_size = 0
for f in sys.argv[1:]:
    tot_size += os.path.getsize(f)

p(tot_size + 8)
p(((BASE + tot_size - 1) | 4095) + 1)
