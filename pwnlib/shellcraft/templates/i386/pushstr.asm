<% from pwnlib.util import lists, packing, fiddling %>\
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
%>\
    /* push ${repr(string)} */
% for word in lists.group(4, string, 'fill', extend)[::-1]:
<%
    sign = packing.u32(word, 'little', 'signed')
%>\
% if sign in [0, 0xa]:
    push ${sign + 1}
    dec byte ptr [esp]
% elif -0x80 <= sign <= 0x7f and okay(word[0]):
    push ${hex(sign)}
% elif okay(word):
    push ${hex(sign)}
% else:
<%
    a,b = fiddling.xor_pair(word, avoid = '\x00\n')
    a   = packing.u32(a, 'little', 'unsigned')
    b   = packing.u32(b, 'little', 'unsigned')
%>\
    push ${hex(a)}
    xor dword ptr [esp], ${hex(b)}
% endif
% endfor
