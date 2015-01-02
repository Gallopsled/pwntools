<% from pwnlib.util import lists, packing, fiddling %>
<% import sys %>
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

    def okay(s):
        return '\n' not in s and '\0' not in s

    if ord(string[-1]) >= 128:
        extend = '\xff'
    else:
        extend = '\x00'
%>

% for word in lists.group(8, string, 'fill', extend)[::-1]:
<%
    sign = packing.u64(word, 'little', 'signed')
%>
% if sign in [0, 0xa]:
    push ${sign + 1}
    dec byte ptr [rsp] /*  ${repr(word)} */
% elif -0x80 <= sign <= 0x7f and okay(word[0]):
    push ${hex(sign)} /*  ${repr(word)} */
% elif -0x80000000 <= sign <= 0x7fffffff and okay(word[:4]):
    push ${hex(sign)} /*  ${repr(word)} */
% elif okay(word):
    /* push ${repr(word)} */
    mov rax, ${hex(sign)}
    push rax
% else:
<%
    a,b = fiddling.xor_pair(word, avoid = '\x00\n')
    a   = packing.u64(a, 'little', 'unsigned')
    b   = packing.u64(b, 'little', 'unsigned')
%>
    /* push ${repr(word)} */
    mov rax, ${hex(a)}
    push rax
    mov rax, ${hex(b)}
    xor [rsp], rax
% endif
% endfor
