<%
    from pwnlib.util import lists, packing, fiddling
    from pwnlib.shellcraft import pretty
    import six
%>\
<%page args="string, append_null = True"/>
<%docstring>
Pushes a string onto the stack without using
null bytes or newline characters.

Example:

    >>> print(shellcraft.amd64.pushstr('').rstrip())
        /* push '\x00' */
        push 1
        dec byte ptr [rsp]
    >>> print(shellcraft.amd64.pushstr('a').rstrip())
        /* push 'a\x00' */
        push 0x61
    >>> print(shellcraft.amd64.pushstr('aa').rstrip())
        /* push 'aa\x00' */
        push 0x1010101 ^ 0x6161
        xor dword ptr [rsp], 0x1010101
    >>> print(shellcraft.amd64.pushstr('aaa').rstrip())
        /* push 'aaa\x00' */
        push 0x1010101 ^ 0x616161
        xor dword ptr [rsp], 0x1010101
    >>> print(shellcraft.amd64.pushstr('aaaa').rstrip())
        /* push 'aaaa\x00' */
        push 0x61616161
    >>> print(shellcraft.amd64.pushstr(b'aaa\xc3').rstrip())
        /* push 'aaa\xc3\x00' */
        mov rax, 0x101010101010101
        push rax
        mov rax, 0x101010101010101 ^ 0xc3616161
        xor [rsp], rax
    >>> print(shellcraft.amd64.pushstr(b'aaa\xc3', append_null = False).rstrip())
        /* push 'aaa\xc3' */
        push -0x3c9e9e9f
    >>> print(shellcraft.amd64.pushstr(b'\xc3').rstrip())
        /* push '\xc3\x00' */
        push 0x1010101 ^ 0xc3
        xor dword ptr [rsp], 0x1010101
    >>> print(shellcraft.amd64.pushstr(b'\xc3', append_null = False).rstrip())
        /* push '\xc3' */
        push -0x3d
    >>> with context.local():
    ...    context.arch = 'amd64'
    ...    print(enhex(asm(shellcraft.pushstr("/bin/sh"))))
    48b801010101010101015048b82e63686f2e72690148310424
    >>> with context.local():
    ...    context.arch = 'amd64'
    ...    print(enhex(asm(shellcraft.pushstr(""))))
    6a01fe0c24
    >>> with context.local():
    ...    context.arch = 'amd64'
    ...    print(enhex(asm(shellcraft.pushstr("\x00", False))))
    6a01fe0c24

Args:
  string (str): The string to push.
  append_null (bool): Whether to append a single NULL-byte before pushing.
</%docstring>
<%
    if isinstance(string, six.text_type):
        string = string.encode('utf-8')
    if append_null and not string.endswith(b'\x00'):
        string += b'\x00'
    if not string:
        return

    def okay(s):
        return b'\n' not in s and b'\0' not in s

    if six.indexbytes(string, -1) >= 128:
        extend = b'\xff'
    else:
        extend = b'\x00'
%>\
    /* push ${repr(string)} */
% for word in lists.group(8, string, 'fill', extend)[::-1]:
<%
    sign = packing.u64(word, endian='little', sign='signed')
    sign32 = packing.u32(word[:4], bits=32, endian='little', sign='signed')
%>\
% if sign in [0, 0xa]:
    push ${pretty(sign + 1)}
    dec byte ptr [rsp]
% elif -0x80 <= sign <= 0x7f and okay(word[:1]):
    push ${pretty(sign)}
% elif -0x80000000 <= sign <= 0x7fffffff and okay(word[:4]):
    push ${pretty(sign)}
% elif okay(word):
    mov rax, ${pretty(sign)}
    push rax
% elif sign32 > 0 and word[4:] == b'\x00\x00\x00\x00':
<%
    a,b = fiddling.xor_pair(word[:4], avoid = b'\x00\n')
    a   = packing.u32(a, endian='little', sign='signed')
    b   = packing.u32(b, endian='little', sign='unsigned')
%>\
    push ${pretty(a)} ^ ${pretty(sign)}
    xor dword ptr [rsp], ${pretty(a)}
% else:
<%
    a,b = fiddling.xor_pair(word, avoid = b'\x00\n')
    a   = packing.u64(a, endian='little', sign='unsigned')
    b   = packing.u64(b, endian='little', sign='unsigned')
%>\
    mov rax, ${pretty(a)}
    push rax
    mov rax, ${pretty(a)} ^ ${pretty(sign)}
    xor [rsp], rax
% endif
% endfor
