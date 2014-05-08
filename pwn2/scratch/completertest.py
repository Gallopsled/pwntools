import pwn2

c1 = pwn2.nonlib.completer.LongestPrefixCompleter([
    'foobar',
    'foobaz',
    'fooquux',
    ])

c2 = pwn2.nonlib.completer.PathCompleter()

with c2:
    s = pwn2.nonlib.readline.readline(prompt = '> ')
    print 'You wrote', s
