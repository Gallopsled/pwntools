<% from pwnlib.util import packing %>
<% from pwnlib.shellcraft import i386 %>
<%page args="value, append_null = True"/>
<%docstring>
Pushes a value onto the stack without using
null bytes or newline characters.

Args:
  value (int,str): The value or register to push
</%docstring>

% if isinstance(value, (int,long)):
${i386.pushstr(packing.pack(value, 32), False)}
% else:
push ${value}
% endif
