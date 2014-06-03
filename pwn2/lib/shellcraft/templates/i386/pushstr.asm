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

    string = string.ljust(pwn.align(4, len(string)), extend)
%>

% for s in pwn.group(4, string)[::-1]:
<%
    n = pwn.u32(s)
    sign = n - (2 * (n & 2**31))
%>\
    % if n == 0:
        push 1
        dec byte [esp] ; ${repr(s)}
    % elif -128 <= sign < 128:
        push `${repr(s)[1:-1]}`
    % elif '\x00' not in s and '\n' not in s:
        push `${repr(s)[1:-1]}`
    % else:
<% a,b = pwn.xor_pair(s, avoid = '\x00\n') %>\
        push `${repr(a)[1:-1]}`
        xor dword [esp], `${repr(b)[1:-1]}` ; ${repr(s)}
    % endif
% endfor
