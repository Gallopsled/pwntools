<% from pwnlib.util import lists, packing, fiddling %>
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
    if not string:
        return

    def okay(s):
        return '\n' not in s and '\0' not in s

    if ord(string[-1]) >= 0x80:
        extend = '\xff'
    else:
        extend = '\x00'

    def pretty(n):
        return hex(n & (2 ** 16 - 1))
%>\
    /* push ${repr(string)} */
% for word in lists.group(2, string, 'fill', extend)[::-1]:
<%
    sign = packing.u16(word, 'little', 'signed')
%>\
% if sign in [0, 0xa]:
    ${pushstr(packing.p16(sign+1))}
    dec byte ptr [esp]
% elif -0x80 <= sign <= 0x7f and okay(word[0]):
    push ${pretty(sign)}
% elif okay(word):
    push ${pretty(sign)}
% else:
<%
    a,b = fiddling.xor_pair(word, avoid = '\x00\n')
    a   = packing.u32(a, 'little', 'unsigned')
    b   = packing.u32(b, 'little', 'unsigned')
%>\
    push ${pretty(a)}
    xor dword ptr [esp], ${pretty(b)}
% endif
% endfor
