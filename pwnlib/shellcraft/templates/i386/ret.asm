<% from pwnlib.shellcraft import i386 %>
<%docstring>A single-byte RET instruction.

Args:
    return_value: Value to return
</%docstring>
<%page args="return_value = None"/>

% if return_value != None:
    ${i386.mov('eax', return_value)}
% endif

    ret
