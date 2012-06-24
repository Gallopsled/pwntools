from core import *

def main():
    """Call /bin/sh. Takes no arguments."""
    return glue('xor ecx, ecx') + template('linux/sh.asm')
