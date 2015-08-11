<%
from pwnlib.shellcraft import pretty, value, common, registers
from pwnlib.shellcraft.amd64 import mov, pushstr, setregs
from pwnlib import constants
%>
<%docstring>
Calculate the length of the specified string.

Arguments:
    string(str): Register or address with the string
    reg(str): Named register to return the value in,
                   rcx is the default.

Example:

    >>> sc  = 'jmp get_str\n'
    >>> sc += 'pop_str: pop rdi\n'
    >>> sc += shellcraft.amd64.strlen('rdi', 'rax')
    >>> sc += 'push rax;'
    >>> sc += shellcraft.amd64.linux.write(1, 'rsp', 8)
    >>> sc += shellcraft.amd64.linux.exit(0)
    >>> sc += 'get_str: call pop_str\n'
    >>> sc += '.asciz "Hello, world\\n"'
    >>> run_assembly(sc).unpack() == len('Hello, world\n')
    True
</%docstring>
<%page args="string, reg='rcx'"/>
    ${setregs({'rcx': -1,
               'rdi': string,
               'rax': 0})}
    repnz scas al, BYTE PTR [rdi]
    inc rcx
    inc rcx
    neg rcx
    ${mov(reg, 'rcx')}
