# import pwn2.lib as lib
import pwn2
lib = pwn2.lib

import time

lib.log.level = 0

n = 0

h = lib.log.waitfor('spinners running', status = '0')

hs = []
while True:
    s = raw_input('> ')
    if s == 'q':
        break
    hs.append(lib.log.waitfor(s, status = 'running'))
    n += 1
    h.status(str(n))

h.success()

for h in hs:
    h.failure()

# lib.log.waitfor('waiting for stuff')
# time.sleep(0.5)
# lib.log.info('something happened')
# time.sleep(0.5)
# lib.log.success('something went well')
# time.sleep(0.5)
# lib.log.waitfor('waiting for some minor stuff')
# time.sleep(0.5)
# lib.log.failure('went wrong')
# raw_input('please hit <enter> ')
# time.sleep(0.5)
# lib.log.done_failure()
# time.sleep(0.5)
# lib.log.info('all in all it went ok')
# time.sleep(0.5)
# lib.log.done_success()


# def foo():
#     plib.log.stub()

# foo()

# try:
#     try:
#         raise KeyError
#     except:
#         plib.log.die('no reason')
# except Exception as e:
#     print `e`
#     # raise
