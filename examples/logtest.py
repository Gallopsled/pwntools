# import pwn2.lib as lib
import pwn
import time

pwn.context.log_level = 0

n = 0

h = pwn.log.waitfor('spinners running', status = '0')

hs = []
while True:
    s = raw_input('> ')
    if s == 'q':
        break
    hs.append(pwn.log.waitfor(s, status = 'running'))
    n += 1
    h.status(str(n))

h.success()

for h in hs:
    h.failure()

# pwn.log.waitfor('waiting for stuff')
# time.sleep(0.5)
# pwn.log.info('something happened')
# time.sleep(0.5)
# pwn.log.success('something went well')
# time.sleep(0.5)
# pwn.log.waitfor('waiting for some minor stuff')
# time.sleep(0.5)
# pwn.log.failure('went wrong')
# raw_input('please hit <enter> ')
# time.sleep(0.5)
# pwn.log.done_failure()
# time.sleep(0.5)
# pwn.log.info('all in all it went ok')
# time.sleep(0.5)
# pwn.log.done_success()


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
