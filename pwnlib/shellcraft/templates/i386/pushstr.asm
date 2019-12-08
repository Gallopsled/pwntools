<%
    from pwnlib.util import lists, packing, fiddling
    from pwnlib.shellcraft import pretty, okay
    import six
%>
<%page args="string, append_null = True"/>
<%docstring>
Pushes a string onto the stack without using
null bytes or newline characters.

Example:

    >>> print(shellcraft.i386.pushstr('').rstrip())
        /* push '\x00' */
        push 1
        dec byte ptr [esp]
    >>> print(shellcraft.i386.pushstr('a').rstrip())
        /* push 'a\x00' */
        push 0x61
    >>> print(shellcraft.i386.pushstr('aa').rstrip())
        /* push 'aa\x00' */
        push 0x1010101
        xor dword ptr [esp], 0x1016060
    >>> print(shellcraft.i386.pushstr('aaa').rstrip())
        /* push 'aaa\x00' */
        push 0x1010101
        xor dword ptr [esp], 0x1606060
    >>> print(shellcraft.i386.pushstr('aaaa').rstrip())
        /* push 'aaaa\x00' */
        push 1
        dec byte ptr [esp]
        push 0x61616161
    >>> print(shellcraft.i386.pushstr('aaaaa').rstrip())
        /* push 'aaaaa\x00' */
        push 0x61
        push 0x61616161
    >>> print(shellcraft.i386.pushstr('aaaa', append_null = False).rstrip())
        /* push 'aaaa' */
        push 0x61616161
    >>> print(shellcraft.i386.pushstr(b'\xc3').rstrip())
        /* push b'\xc3\x00' */
        push 0x1010101
        xor dword ptr [esp], 0x10101c2
    >>> print(shellcraft.i386.pushstr(b'\xc3', append_null = False).rstrip())
        /* push b'\xc3' */
        push -0x3d
    >>> with context.local():
    ...    context.arch = 'i386'
    ...    print(enhex(asm(shellcraft.pushstr("/bin/sh"))))
    68010101018134242e726901682f62696e
    >>> with context.local():
    ...    context.arch = 'i386'
    ...    print(enhex(asm(shellcraft.pushstr(""))))
    6a01fe0c24
    >>> with context.local():
    ...    context.arch = 'i386'
    ...    print(enhex(asm(shellcraft.pushstr("\x00", False))))
    6a01fe0c24

Args:
  string (str): The string to push.
  append_null (bool): Whether to append a single NULL-byte before pushing.
</%docstring>
<%
original = string
string   = packing.flat(string)

if append_null:
    string += b'\x00'
    if isinstance(original, six.binary_type):
        original += b'\x00'
    elif isinstance(original, six.text_type):
        original += '\x00'

if not string:
    return

if six.indexbytes(string, -1) >= 128:
    extend = b'\xff'
else:
    extend = b'\x00'
%>\
    /* push ${pretty(original, False)} */
% for word in lists.group(4, string, 'fill', extend)[::-1]:
<%
    sign = packing.u32(word, endian='little', sign='signed')
%>\
% if sign in [0, 0xa]:
    push ${pretty(sign + 1)}
    dec byte ptr [esp]
% elif -0x80 <= sign <= 0x7f and okay(word[:1]):
    push ${pretty(sign)}
% elif okay(word):
    push ${pretty(sign)}
% else:
<%
    a,b = fiddling.xor_pair(word, avoid = b'\x00\n')
    a   = packing.u32(a, endian='little', sign='unsigned')
    b   = packing.u32(b, endian='little', sign='unsigned')
%>\
    push ${pretty(a)}
    xor dword ptr [esp], ${pretty(b)}
% endif
% endfor
