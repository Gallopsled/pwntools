"""
Just a lot of spinners!
"""

from pwn import *

context.log_level = 0

n = 1
h = log.waitfor('spinners running', status = str(n))

hs = []
print('type "q" to quit')
while True:
    s = str_input('> ').strip()
    if s == 'q':
        break
    hs.append(log.waitfor(s, status = 'running'))
    n += 1
    h.status(str(n))

h.success()

for h in hs:
    h.failure()
