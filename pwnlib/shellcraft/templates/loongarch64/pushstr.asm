<%
    from pwnlib.util import lists, packing, fiddling
    from pwnlib.shellcraft import loongarch64, pretty
%>\
<%page args="string, append_null = True"/>
<%docstring>
Pushes a string onto the stack.

There is no effort done to avoid newlines and null bytes in the generated code.

Register t8 is not guaranteed to be preserved.

Example:

    >>> print(shellcraft.loongarch64.pushstr('').rstrip())
        st.d     $r0, -8(sp)
    >>> print(shellcraft.loongarch64.pushstr('a').rstrip())
        li.d     $t8, 97
        addi.d   $sp, $sp, -8
        st.d     $t8, $sp, 0
    >>> print(shellcraft.loongarch64.pushstr('aa').rstrip())
        li.d     $t8, 24929
        addi.d   $sp, $sp, -8
        st.d     $t8, $sp, 0
    >>> print(shellcraft.loongarch64.pushstr('aaaa').rstrip())
        li.d     $t8, 1633771873
        addi.d   $sp, $sp, -8
        st.d     $t8, $sp, 0
    >>> print(shellcraft.loongarch64.pushstr('aaaaa').rstrip())
        li.d     $t8, 418245599585
        addi.d   $sp, $sp, -8
        st.d     $t8, $sp, 0
    >>> print(shellcraft.loongarch64.pushstr('aaaa', append_null = False).rstrip())
        li.d     $t8, 1633771873
        addi.d   $sp, $sp, -8
        st.d     $t8, $sp, 0
    >>> print(shellcraft.loongarch64.pushstr(b'\xc3').rstrip())
        li.d     $t8, 195
        addi.d   $sp, $sp, -8
        st.d     $t8, $sp, 0
    >>> print(shellcraft.loongarch64.pushstr(b'\xc3', append_null = False).rstrip())
        li.d     $t8, 195
        addi.d   $sp, $sp, -8
        st.d     $t8, $sp, 0

Args:
  string (str): The string to push.
  append_null (bool): Whether to append a single NULL-byte before pushing.
</%docstring>
<%
    if isinstance(string, str):
        string = string.encode('utf-8')
    if append_null:
        string += b'\x00'
    if not string:
        return

    split_string = lists.group(8, string, 'fill', b'\x00')
    stack_offset = len(split_string) * -8
%>\
% for index, word in enumerate(split_string):
% if word == b'\x00\x00\x00\x00\x00\x00\x00\x00':
    st.d     $r0, ${stack_offset+(8 * index)}(sp)
<%
    continue
%>\
% endif
<%
    word = packing.u64(word, sign=True)
%>\
    ${loongarch64.push(word)}
% endfor
