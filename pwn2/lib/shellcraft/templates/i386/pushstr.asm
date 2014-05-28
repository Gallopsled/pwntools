<%page args="string, exact = False"/>
<%docstring>
    Pushes a string onto the stack without using
    null bytes or newline characters.
</%docstring>

<%
    if not exact:
        string = string.rstrip('\x00') + '\x00'
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
