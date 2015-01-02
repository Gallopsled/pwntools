<% from pwnlib.util import packing %>
<% from pwnlib.shellcraft import i386 %>
<%page args="value, append_null = True"/>
<%docstring>
Pushes a value onto the stack without using
null bytes or newline characters.

Args:
  value (int): The string to push.
</%docstring>

${i386.pushstr(packing.pack(value, 'all'), False)}
