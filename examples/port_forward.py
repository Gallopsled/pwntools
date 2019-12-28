"""
A very simple port forwarder using `pwnlib.tubes.tube.connect_both()`.
"""

from pwn import *

while True:
    listen(1337).wait_for_connection().connect_both(remote('google.com', 80))

# now point your browser (or curl(1)) to http://localhost:1337
