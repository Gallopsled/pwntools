<% from pwnlib.util import lists, packing, fiddling %>
<% from pwnlib.shellcraft.arm import push %>
<%page args="string, append_null = True"/>
<%docstring>
Pushes a string onto the stack.

Args:
  string (str): The string to push.
  append_null (bool): Whether to append a single NULL-byte before pushing.
</%docstring>
<%
    if append_null:
        string += '\x00'

    while len(string) % 4:
        string += '\x41'
%>\
    /* push ${repr(string)} */
% for word in packing.unpack_many(string, 32)[::-1]:
    ${push(word)}
% endfor
