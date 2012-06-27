from pwn.internal.shellcraft import *

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
codes = ['sh',
         'dup',
         'listen',
         'connect',
         'connectback',
         'bindshell',
         'acceptloop']

load(codes)
