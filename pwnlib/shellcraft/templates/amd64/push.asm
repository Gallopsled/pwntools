<% from pwnlib.util import packing %>
<% from pwnlib.shellcraft import amd64 %>
<% import re %>
<%page args="value"/>
<%docstring>
Pushes a value onto the stack without using
null bytes or newline characters.

Args:
  value (int,str): The value or register to push
</%docstring>

% if isinstance(value, (int,long)):
    /* push ${repr(value)} */
    ${re.sub(r'^\s*/.*\n', '', amd64.pushstr(packing.pack(value, 64, 'little', True), False), 1)}
% else:
    push ${value}
% endif
