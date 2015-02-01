"""
"Easteregg"
"""

from binjitsu import *

splash()

h = log.waitfor("You wrote", status = "--")

while True:
    l = raw_input('> ')
    h.status(l.upper())
