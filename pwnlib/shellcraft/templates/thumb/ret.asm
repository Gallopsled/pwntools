<% from pwnlib.shellcraft import thumb %>
<%docstring>A single-byte RET instruction.

Args:
    return_value: Value to return
</%docstring>
<%page args="return_value = None"/>

% if return_value != None:
    ${thumb.mov('r0', return_value)}
% endif

    bx lr
