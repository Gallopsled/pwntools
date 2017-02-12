<%
from pwnlib.shellcraft import pretty, common, registers
from pwnlib.shellcraft.i386 import mov, pushstr, setregs
from pwnlib import constants
%>
<%docstring>
Calculate the length of the specified string.

Arguments:
    string(str): Register or address with the string
    reg(str): Named register to return the value in,
                   ecx is the default.

Example:

    >>> sc  = 'jmp get_str\n'
    >>> sc += 'pop_str: pop eax\n'
    >>> sc += shellcraft.i386.strlen('eax')
    >>> sc += 'push ecx;'
    >>> sc += shellcraft.i386.linux.write(1, 'esp', 4)
    >>> sc += shellcraft.i386.linux.exit(0)
    >>> sc += 'get_str: call pop_str\n'
    >>> sc += '.asciz "Hello, world\\n"'
    >>> run_assembly(sc).unpack() == len('Hello, world\n')
    True
</%docstring>
<%page args="string, reg='ecx'"/>
    ${setregs({'ecx': -1,
               'edi': string,
               'eax': 0})}
    repnz scas al, BYTE PTR [edi]
    inc ecx
    inc ecx
    neg ecx
    ${mov(reg, 'ecx')}
