import pwn2

c1 = pwn2.nonlib.completer.LongestPrefixCompleter([
    'foobar',
    'foobaz',
    'fooquux',
    ])

c2 = pwn2.nonlib.completer.PathCompleter(mask = '*.py')

with c2:
    while True:
        s = pwn2.nonlib.readline.readline(prompt = '> ')
        print 'You wrote', s
