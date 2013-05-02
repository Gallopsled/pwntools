from pwn import *
from random import randrange, random

import sys

# sys.stdout.write('\x1b[sfoo\nbar\nbaz\n\x1b[uqux\n')

log.waitfor('Phew... working')
progress = [0] * 8
for i in range(100):
    s = '\n'.join(('\x1b[1m\x1b[3%dm.\x1b[m' % k) * n for k, n in enumerate(progress))
    progress[randrange(len(progress))] += 1 if random() > 0.2 else -1
    log.status(s)
    sleep(0.1)
log.succeeded()
print 'yolo'
