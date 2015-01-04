<% from pwnlib.util import packing %>
<% from pwnlib.shellcraft import amd64 %>
<%page args="value, append_null = True"/>
<%docstring>
Pushes a value onto the stack without using
null bytes or newline characters.

Args:
  value (int,str): The value or register to push
</%docstring>

% if isinstance(value, (int,long)):
${amd64.pushstr(packing.pack(value, 64), False)}
% else:
push ${value}
% endif

