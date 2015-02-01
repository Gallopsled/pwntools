"""
A very simple port forwarder using `pwnlib.tubes.tube.connect_both()`.  Notice
that `<>` is just a shorthand.
"""

from binjitsu import *

while True:
    listen(1337).wait_for_connection() <> remote('google.com', 80)

# now point your browser (or curl(1)) to http://localhost:1337
