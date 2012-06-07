from core import *
arch = MIPS
def main():
    """Call /bin/sh. Takes no arguments."""
    return asm('xor ecx, ecx') + template('linux/sh.asm')
