
# import sys
# class Wrapper:
#     def __init__(self, fd):
#         self._fd = fd
#     def readline(self, size = None):
#         return ''
#     def __getattr__(self, k):
#         return self._fd.__getattribute__(k)
# sys.stdin = Wrapper(sys.stdin)
# print `raw_input()`

import readline
import pwn
raw_input('> ')
