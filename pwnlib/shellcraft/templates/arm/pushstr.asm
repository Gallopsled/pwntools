<% from pwnlib.util import lists, packing, fiddling %>
<% from pwnlib.shellcraft.arm import push %>
<%page args="string, append_null = True, register='r7'"/>
<%docstring>
Pushes a string onto the stack.

Args:
    string (str): The string to push.
    append_null (bool): Whether to append a single NULL-byte before pushing.
    register (str): Temporary register to use.  By default, R7 is used.

Examples:

.. doctest::
   :skipif: not binutils_arm or not qemu_arm

    >>> print shellcraft.arm.pushstr("Hello!").rstrip()
        /* push 'Hello!\x00A' */
        movw r7, #0x4100216f & 0xffff
        movt r7, #0x4100216f >> 16
        push {r7}
        movw r7, #0x6c6c6548 & 0xffff
        movt r7, #0x6c6c6548 >> 16
        push {r7}

</%docstring>
<%
    if append_null:
        string += '\x00'

    while len(string) % 4:
        string += '\x41'
%>\
    /* push ${repr(string)} */
% for word in packing.unpack_many(string, 32)[::-1]:
    ${push(word, register)}
% endfor
