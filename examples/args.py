"""
When not in lib-mode (import `pwn` rather than `pwnlib`) we parse the
commandline for variables definitions.  A variable definition has the form::

  <var>=<val>

where ``<var>`` contains only uppercase letters, digits and underscores and
doesn't start with a digit.

Try running this example with::

  $ python args.py RHOST=localhost RPORT=1337
"""

from pwn import *

print(args['RHOST'] or 'RHOST is not set')
print(args['RPORT'] or 'RPORT is not set')
