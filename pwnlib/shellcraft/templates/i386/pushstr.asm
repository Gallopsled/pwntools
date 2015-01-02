<% from pwnlib.util import lists, packing, fiddling %>
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

    if ord(string[-1]) >= 128:
        extend = '\xff'
    else:
        extend = '\x00'
%>

% for word in lists.group(4, string, 'fill', extend)[::-1]:
<%
    sign = packing.u32(word, 'little', 'unsigned')
%>
% if sign == 0:
    push 1
    dec byte ptr [esp] /*  ${repr(word)} */
% elif '\x00' not in word and '\n' not in word:
    push ${hex(sign)} /*  ${repr(word)} */
% else:
<%
    a,b = fiddling.xor_pair(word, avoid = '\x00\n')
    a   = packing.u32(a, 'little', False)
    b   = packing.u32(b, 'little', False)
%>
    /* push ${repr(word)} */
    push ${hex(a)}
    xor dword ptr [esp], ${hex(b)}
% endif
% endfor
