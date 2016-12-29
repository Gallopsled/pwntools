#!/usr/bin/env python

import sys
from . import question

class WebExploitTemplate():
    name = 'web'
    summary = 'New HTTP-based exploit'

    def build(self):
        base = """
#!/usr/bin/env python
from pwn import *

http_pkt = "GET / HTTP/1.1\\r\\n"\\
           "User Agent: %s\\r\\n" % useragents.random()

sock = remote("{host}", {port})
sock.send(http_pkt)
log.info(sock.recvline())
"""
        host = question("Hostname", "example.com")
        port = question("Port", 80)

        return base.format(host=host, port=port)
