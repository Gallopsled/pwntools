"""
Example showing pwnlib's readline implementation and a few completers.  This
part of pwnlib will probably see some major changes soon, but we wanted to show
off some proof-of-concepts.
"""

from pwn import *
from pwnlib.term.completer import LongestPrefixCompleter
from pwnlib.term.completer import PathCompleter

c1 = LongestPrefixCompleter([
    'foobar',
    'foobaz',
    'fooqux',
    'exit',
    'enough!',
    ])

c2 = PathCompleter(mask = '*.py')

with c1:
    print 'type "exit" to exit'
    while True:
        s = term.readline.readline(prompt = '> ').strip()
        if s in ('exit', 'enough!'):
            break
        print 'You wrote', s
with c2:
    print 'choose a file'
    s = term.readline.readline(prompt = text.bold_green('$ ')).strip()
    print 'You picked', s
