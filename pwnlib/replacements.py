"""Improved eplacements for standard functions
"""

import time as __time

def sleep(n):
    end = __time.time() + n
    while True:
        left = end - __time.time()
        if left <= 0:
            break
        __time.sleep(left)
