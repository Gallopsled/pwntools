from pwn.shellcraft import *

_header = """
%include "linux/32.asm"
%include "macros/macros.asm"
bits 32
"""

def _assemble(src):
    out = ['nasm']
    if DEBUG:
        out += ['-D', 'DEBUG']
    out += ['-I', INCLUDE + '/nasm/', '-o' ,'/dev/stdout', src]
    return out

assemble = gen_assembler(_header, _assemble)

# Codes
from sh           import sh
from dup          import dup
from listen       import listen
from connect      import connect
from connectback  import connectback
from bindshell    import bindshell
