<%
    from pwnlib.util import lists, packing, fiddling
    from pwnlib.shellcraft import riscv64, pretty
    import six
%>\
<%page args="string, append_null = True"/>
<%docstring>
Pushes a string onto the stack without using
null bytes or newline characters.

Example:

    >>> print(shellcraft.riscv64.pushstr('').rstrip())
        /* push b'\x00' */
        sw zero, -8(sp)
        addi sp, sp, -8
    >>> print(shellcraft.riscv64.pushstr('a').rstrip())
        /* push b'a\x00' */
        /* mv t4, 0x61 */
        xori t4, zero, 0x79e
        xori t4, t4, 0x7ff
        sd t4, -8(sp)
        addi sp, sp, -8
    >>> print(shellcraft.riscv64.pushstr('aa').rstrip())
        /* push b'aa\x00' */
        li t4, 0x6161
        sd t4, -8(sp)
        addi sp, sp, -8
    >>> print(shellcraft.riscv64.pushstr('aaaa').rstrip())
        /* push b'aaaa\x00' */
        /* mv t4, 0x61616161 */
        lui t4, 0x61616
        xori t4, t4, 0x161
        sd t4, -8(sp)
        addi sp, sp, -8
    >>> print(shellcraft.riscv64.pushstr('aaaaa').rstrip())
        /* push b'aaaaa\x00' */
        li t4, 0x6161616161
        sd t4, -8(sp)
        addi sp, sp, -8
    >>> print(shellcraft.riscv64.pushstr('aaaa', append_null = False).rstrip())
        /* push b'aaaa' */
        /* mv t4, 0x61616161 */
        lui t4, 0x61616
        xori t4, t4, 0x161
        sd t4, -8(sp)
        addi sp, sp, -8
    >>> print(shellcraft.riscv64.pushstr(b'\xc3').rstrip())
        /* push b'\xc3\x00' */
        /* mv t4, 0xc3 */
        xori t4, zero, 0x73c
        xori t4, t4, 0x7ff
        sd t4, -8(sp)
        addi sp, sp, -8
    >>> print(shellcraft.riscv64.pushstr(b'\xc3', append_null = False).rstrip())
        /* push b'\xc3' */
        /* mv t4, 0xc3 */
        xori t4, zero, 0x73c
        xori t4, t4, 0x7ff
        sd t4, -8(sp)
        addi sp, sp, -8
    >>> print(enhex(asm(shellcraft.riscv64.pushstr("/bin/sh"))))
    b79e39349b8e7e7bb20e938ebe34b60e938efe22233cd1ff6111
    >>> print(enhex(asm(shellcraft.riscv64.pushstr(""))))
    232c01fe6111
    >>> print(enhex(asm(shellcraft.riscv64.pushstr("\x00", append_null =  False))))
    232c01fe6111

Args:
  string (str): The string to push.
  append_null (bool): Whether to append a single NULL-byte before pushing.
</%docstring>
<%
    if isinstance(string, six.text_type):
        string = string.encode('utf-8')
    if append_null:
        string += b'\x00'
    if not string:
        return

    split_string = lists.group(8, string, 'fill', b'\x00')
    stack_offset = len(split_string) * -8
%>\
    /* push ${pretty(string, False)} */
% for index, word in enumerate(split_string):
% if word == b'\x00\x00\x00\x00\x00\x00\x00\x00':
    sw zero, ${stack_offset+(8 * index)}(sp)
<%
    continue
%>\
% endif
<%
    word = packing.u64(word, sign=True)
%>\
    ${riscv64.mov('t4', word)}
    sd t4, ${stack_offset+(8 * index)}(sp)
% endfor
    addi sp, sp, ${stack_offset}
