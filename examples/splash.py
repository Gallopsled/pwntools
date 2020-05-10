"""
"Easteregg"
"""

from pwn import *

splash()

h = log.waitfor("You wrote", status = "--")

while True:
    l = str_input('> ').strip()
    h.status(l.upper())
