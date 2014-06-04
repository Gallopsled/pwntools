import pwn
import pwnlib.term.completer

c1 = pwn.term.completer.LongestPrefixCompleter([
    'foobar',
    'foobaz',
    'fooquux',
    ])

c2 = pwn.term.completer.PathCompleter(mask = '*.py')

with c1:
    while True:
        s = pwn.term.readline.readline(prompt = '> ')
        print 'You wrote', s
