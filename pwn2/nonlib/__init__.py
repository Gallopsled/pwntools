import pwn2
pwn2.libmode = False

# setup the terminal
import term
pwn2.hasterm = term.available
import stdin

# promote to top-level
from toplevel import *
