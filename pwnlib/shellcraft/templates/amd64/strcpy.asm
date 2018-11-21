<%
from pwnlib.shellcraft import pretty, common, registers
from pwnlib.shellcraft.amd64 import mov, pushstr, setregs
from pwnlib import constants
%>
<%docstring>
Copies a string

Example:

    >>> sc  = 'jmp get_str\n'
    >>> sc += 'pop_str: pop rax\n'
    >>> sc += shellcraft.amd64.strcpy('rsp', 'rax')
    >>> sc += shellcraft.amd64.linux.write(1, 'rsp', 32)
    >>> sc += shellcraft.amd64.linux.exit(0)
    >>> sc += 'get_str: call pop_str\n'
    >>> sc += '.asciz "Hello, world\\n"'
    >>> run_assembly(sc).recvline()
    b'Hello, world\n'
</%docstring>
<%page args="dst, src"/>
    ${setregs({'rcx': -1,
               'rdi': src,
               'rsi': dst,
               'rax': 0})}
    push rdi
    repnz scas al, BYTE PTR [rdi]
    pop rdi
    xchg rdi, rsi
    inc rcx
    neg rcx
    rep movs BYTE PTR [rdi], BYTE PTR [rsi]
