"""Improved replacements for standard functions
"""

import time as __time


def sleep(n):
    """sleep(n)

    Replacement for :func:`time.sleep()`, which does not return if a signal is received.

    Arguments:
      n (int):  Number of seconds to sleep.
    """
    end = __time.time() + n
    while True:
        left = end - __time.time()
        if left <= 0:
            break
        __time.sleep(left)
