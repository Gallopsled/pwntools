<%
  from pwnlib.util import lists, packing, fiddling
  from pwnlib.shellcraft import mips
%>
<%page args="string, append_null = True"/>
<%docstring>
Pushes a string onto the stack without using
null bytes or newline characters.

Args:
  string (str): The string to push.
  append_null (bool): Whether to append a single NULL-byte before pushing.
</%docstring>
<%
    if append_null:
        string += '\x00'
    if not string:
        return
%>\
    /* push ${repr(string)} */
% for word in lists.group(4, string, 'fill', '\x00')[::-1]:
    ${mips.mov('$at', packing.unpack(word))}
    sw $at, -4($sp)
    add $sp, $sp, -4
% endfor
