from shellcraft import *
arch = INTEL
def main():
    """Call /bin/sh. Takes no arguments."""
    return asm('xor eax, eax') + template('freebsd/sh.asm', {})
