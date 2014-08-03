"""
Another example showing interconnection of sockets.  This script will wait for
three connections on port 1337, then connect them like a three-way Uroboros.
"""

from pwn import *

cs = [listen(1337) for _ in range(3)]

cs[0] << cs[1] << cs[2] << cs[0]

cs[0].wait()
cs[1].wait()
cs[2].wait()
