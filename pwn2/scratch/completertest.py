import pwn2

c = pwn2.nonlib.completer.LongestPrefixCompleter([
    'foobar',
    'foobaz',
    'fooquux',
    ])

with c:
    s = pwn2.nonlib.readline.readline(prompt = '> ')
    print 'You wrote', s
