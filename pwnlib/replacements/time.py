time = __import__('time')

def sleep(n):
    end = time.time() + n
    while True:
        left = end - time.time()
        if left <= 0:
            break
        time.sleep(left)
