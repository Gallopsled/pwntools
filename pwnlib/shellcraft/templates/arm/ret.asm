<% from pwnlib.shellcraft import arm %>
<%docstring>A single-byte RET instruction.

Args:
    return_value: Value to return
</%docstring>
<%page args="return_value = None"/>

% if return_value != None:
    ${arm.mov('r0', return_value)}
% endif

    bx lr
