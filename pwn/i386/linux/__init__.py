from pwn.internal.shellcraft import *
from .. import *

_header = """
%include "linux/32.asm"
%include "macros/macros.asm"
bits 32
"""

def _asm(src):
    out = ['nasm']
    if DEBUG:
        out += ['-D', 'DEBUG']
    out += ['-I', INCLUDE + '/nasm/', '-o' ,'/dev/stdout', src]
    return out

asm = gen_assembler(_header, _asm)

# Codes
load(['sh',
      'fakesh',
      'dup',
      'dupsh',
      'listen',
      'connect',
      'connectback',
      'bindshell',
      'acceptloop',
      'setperms',
      'fork',
      'echo'])
