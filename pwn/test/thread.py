from pwn import Thread, sleep, pause

def f(n):
    try:
        while True:
            sleep(0.001)
    finally:
        print 'EXIT', n

ts = [Thread(target = f, args = (n,)) for n in range(10)]
for t in ts:
    t.start()

pause()

for t in ts:
    t.sigterm()

for t in ts:
    t.join()
