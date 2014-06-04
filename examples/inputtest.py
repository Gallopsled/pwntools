# raise Exception('1234')

# import sys
# _write = sys.stdout.write
# class Proxy:
#     def __init__(self, fd):
#         self._fd = fd
#     def readline(self):
#         _write('Input plox: ')
#         return self._fd.readline()
#     def read(self, n):
#         _write('xxx')
#         return self._fd.read(n)
#     def __getattr__(self, k):
#         # _write('[%s]\n' % k)
#         return self._fd.__getattribute__(k)

# # sys.stdout = Proxy(sys.stdout)
# sys.stdin = Proxy(sys.stdin)

# print raw_input()


import pwn
import pwnlib.term.readline

h = pwn.term.output('yolo\n')
i = 0
def foo (_):
    global i
    i += 1
    pwn.term.output('foooooo%d\n' % i, frozen = True, before = h)

def bar ():
    print

def baz (_):
    import sys
    sys.exit()

pwnlib.term.readline.startup_hook = bar
pwnlib.term.readline.keymap.register({
    'C-x C-a': foo,
    'C-x C-s': baz,
    })

while True:
    print raw_input('> ')
