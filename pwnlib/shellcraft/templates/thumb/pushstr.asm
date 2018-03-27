<%
  from pwnlib.shellcraft import thumb
  from pwnlib.util import lists, packing
  import six
%>
<%page args="string, append_null = True, register = 'r7'"/>
<%docstring>
Pushes a string onto the stack without using
null bytes or newline characters.

Args:
  string (str): The string to push.
  append_null (bool): Whether to append a single NULL-byte before pushing.

Examples:

Note that this doctest has two possibilities for the first result, depending
on your version of binutils.

    >>> enhex(asm(shellcraft.pushstr('Hello\nWorld!', True))) in [
    ... '87ea070780b4dff8047001e0726c642180b4dff8047001e06f0a576f80b4dff8047001e048656c6c80b4',
    ... '87ea070780b4dff8067000f002b8726c642180b4dff8047000f002b86f0a576f80b4014f00f002b848656c6c80b4']
    True
    >>> print(shellcraft.pushstr('abc').rstrip()) #doctest: +ELLIPSIS
        /* push 'abc\x00' */
        ldr r7, value_...
        b value_..._after
    value_...: .word 0xff636261
    value_..._after:
        lsl r7, #8
        lsr r7, #8
        push {r7}
    >>> print(enhex(asm(shellcraft.pushstr('\x00', False))))
    87ea070780b4

</%docstring>
<%
    if isinstance(string, six.text_type):
        string = string.encode('utf-8')
    if append_null:
        string += b'\x00'
    if not string:
        return

    offset = len(string)
    while offset % 4:
        offset += 1
%>\
    /* push ${repr(string)} */
% for word in lists.group(4, string, 'fill', b'\x00')[::-1]:
    ${thumb.mov(register, packing.unpack(word))}
    push {${register}}
% endfor
