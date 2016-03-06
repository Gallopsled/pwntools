<% from pwnlib.shellcraft import amd64 %>
<%docstring>A single-byte RET instruction.

Args:
    return_value: Value to return
</%docstring>
<%page args="return_value = None"/>

% if return_value != None:
    ${amd64.mov('rax', return_value)}
% endif

    ret
