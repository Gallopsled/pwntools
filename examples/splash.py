"""
"Easteregg"
"""

from pwn import *

splash()

h = log.waitfor("You wrote", status = "--")

while True:
    l = raw_input('> ')
    h.status(l.upper())
