<%
    from pwnlib.util import lists, packing, fiddling
    from pwnlib.shellcraft import mips, pretty
    import six
%>\
<%page args="string, append_null = True"/>
<%docstring>
Pushes a string onto the stack without using
null bytes or newline characters.

Example:

    >>> print(shellcraft.mips.pushstr('').rstrip())
        /* push b'\x00' */
        sw $zero, -4($sp)
        addiu $sp, $sp, -4
    >>> print(shellcraft.mips.pushstr('a').rstrip())
        /* push b'a\x00' */
        li $t9, ~0x61
        not $t1, $t9
        sw $t1, -4($sp)
        addiu $sp, $sp, -4
    >>> print(shellcraft.mips.pushstr('aa').rstrip())
        /* push b'aa\x00' */
        ori $t1, $zero, 24929
        sw $t1, -4($sp)
        addiu $sp, $sp, -4
    >>> print(shellcraft.mips.pushstr('aaa').rstrip())
        /* push b'aaa\x00' */
        li $t9, ~0x616161
        not $t1, $t9
        sw $t1, -4($sp)
        addiu $sp, $sp, -4
    >>> print(shellcraft.mips.pushstr('aaaa').rstrip())
        /* push b'aaaa\x00' */
        li $t1, 0x61616161
        sw $t1, -8($sp)
        sw $zero, -4($sp)
        addiu $sp, $sp, -8
    >>> print(shellcraft.mips.pushstr('aaaaa').rstrip())
        /* push b'aaaaa\x00' */
        li $t1, 0x61616161
        sw $t1, -8($sp)
        li $t9, ~0x61
        not $t1, $t9
        sw $t1, -4($sp)
        addiu $sp, $sp, -8
    >>> print(shellcraft.mips.pushstr('aaaa', append_null = False).rstrip())
        /* push b'aaaa' */
        li $t1, 0x61616161
        sw $t1, -4($sp)
        addiu $sp, $sp, -4
    >>> print(shellcraft.mips.pushstr(b'\xc3').rstrip())
        /* push b'\xc3\x00' */
        li $t9, ~0xc3
        not $t1, $t9
        sw $t1, -4($sp)
        addiu $sp, $sp, -4
    >>> print(shellcraft.mips.pushstr(b'\xc3', append_null = False).rstrip())
        /* push b'\xc3' */
        li $t9, ~0xc3
        not $t1, $t9
        sw $t1, -4($sp)
        addiu $sp, $sp, -4
    >>> print(enhex(asm(shellcraft.mips.pushstr("/bin/sh"))))
    696e093c2f622935f8ffa9af97ff193cd08c393727482003fcffa9aff8ffbd27
    >>> print(enhex(asm(shellcraft.mips.pushstr(""))))
    fcffa0affcffbd27
    >>> print(enhex(asm(shellcraft.mips.pushstr("\x00", False))))
    fcffa0affcffbd27

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

    def get_offset(nib):
        num = 0
        # Ensure we don't overflow our existing nibble
        if nib[0] == b'\xff':
            num = 3
        else:
            num = 0x101
        return num

    split_string = lists.group(4, string, 'fill', b'\x00')
    stack_offset = len(split_string) * -4
%>\
    /* push ${pretty(string, False)} */
% for index, word in enumerate(split_string):
% if word == b'\x00\x00\x00\x00':
    sw $zero, ${stack_offset+(4 * index)}($sp)
<%
    continue
%>\
% endif
<%
    word = packing.u32(word, sign=True)
%>\
    ${mips.mov('$t1', word)}
    sw $t1, ${stack_offset+(4 * index)}($sp)
% endfor
    addiu $sp, $sp, ${stack_offset}
