<% from pwnlib.shellcraft import arm %>
<%docstring>A single-byte RET instruction.

Args:
    return_value: Value to return

Examples:
    >>> with context.local(arch='arm'):
    ...     print enhex(asm(shellcraft.ret()))
    ...     print enhex(asm(shellcraft.ret(0)))
    ...     print enhex(asm(shellcraft.ret(0xdeadbeef)))
    1eff2fe1
    000020e01eff2fe1
    ef0e0be3ad0e4de31eff2fe1
</%docstring>
<%page args="return_value = None"/>

% if return_value != None:
    ${arm.mov('r0', return_value)}
% endif

    bx lr
