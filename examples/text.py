'''
Example showing how to use `pwnlib.term.text`.

Try running with::

  $ TERM=xterm python text.py

and::

  $ TERM=xterm-256color python text.py
'''
from pwn import *

s = 'hello from pwntools'
print(text.black_on_green(s))
print(text.black_on_bright_green(s))
print(text.green_on_black(s))
print(text.bright_green_on_black(s))
print(text.bold_green_on_black(s))
