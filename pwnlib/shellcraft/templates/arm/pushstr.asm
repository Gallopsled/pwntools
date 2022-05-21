<% from pwnlib.util import lists, packing, fiddling %>
<% from pwnlib.shellcraft.arm import push %>
<% from pwnlib.shellcraft import pretty %>
<% import six %>
<%page args="string, append_null = True, register='r7'"/>
<%docstring>
Pushes a string onto the stack.

Args:
    string (str): The string to push.
    append_null (bool): Whether to append a single NULL-byte before pushing.
    register (str): Temporary register to use.  By default, R7 is used.

Examples:

    >>> print(shellcraft.arm.pushstr("Hello!").rstrip())
        /* push b'Hello!\x00A' */
        movw r7, #0x4100216f & 0xffff
        movt r7, #0x4100216f >> 16
        push {r7}
        movw r7, #0x6c6c6548 & 0xffff
        movt r7, #0x6c6c6548 >> 16
        push {r7}

</%docstring>
<%
    if isinstance(string, six.text_type):
        string = string.encode('utf-8')

    if append_null:
        string += b'\x00'

    while len(string) % 4:
        string += b'\x41'
%>\
    /* push ${pretty(string, False)} */
% for word in packing.unpack_many(string, 32)[::-1]:
    ${push(word, register)}
% endfor
