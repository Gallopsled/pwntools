import pwn2 as __pwn__
__pwn__.__libmode__ = False

# setup the terminal
import term
__pwn__.__hasterm__ = term.available
import stdin
