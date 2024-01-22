<%
  from pwnlib import shellcraft as SC
  from pwnlib import constants
  from pwnlib.context import context as ctx # Ugly hack, mako will not let it be called context
  from pwnlib.log import getLogger
  from pwnlib.util.lists import group
  from pwnlib.util.packing import p16, u16, pack, unpack
  from pwnlib.util.fiddling import xor_pair
  from pwnlib.shellcraft import pretty
  from pwnlib.shellcraft.registers import aarch64 as regs
  import six
  log = getLogger('pwnlib.shellcraft.arm.mov')
%>
<%page args="dst, src"/>
<%docstring>
Move src into dest.

Support for automatically avoiding newline and null bytes has to be done.

If src is a string that is not a register, then it will locally set
`context.arch` to `'arm'` and use :func:`pwnlib.constants.eval` to evaluate the
string. Note that this means that this shellcode can change behavior depending
on the value of `context.os`.

Examples:

    >>> print(shellcraft.mov('x0','x1').rstrip())
        mov  x0, x1
    >>> print(shellcraft.mov('x0','0').rstrip())
        mov  x0, xzr
    >>> print(shellcraft.mov('x0', 9).rstrip())
        mov  x0, #9
    >>> print(shellcraft.mov('x0', 0x94532).rstrip())
        /* Set x0 = 607538 = 0x94532 */
        mov  x0, #17714
        movk x0, #9, lsl #16

Args:
  dest (str): The destination register.
  src (str): Either the input register, or an immediate value.
</%docstring>
<%
if dst not in regs:
    log.error('%r is not a register' % str(dst))

if not src in regs:
    src = SC.eval(src)

mov_x15 = None
xor     = None


if isinstance(src, six.integer_types):
    lobits = dst not in ('x0', 'x10')
    packed = pack(src)
    words  = group(2, packed)
    xor    = [b'\x00\x00'] * 4

    for i, word in enumerate(list(words)):
        # If an entire word is zero, we can work around it.
        # However, if any of the individual bytes are '\n', or only
        # one of the bytes is a zero, we must do an XOR.
        if word == b'\x00\x00': continue

        w = p16((u16(word) & 0x7ff) << 5 | lobits)
        if b'\n' not in w and b'\x00' not in w:
            if u16(word) & 7 == 0 and not lobits:
                mov_x15 = dst
                dst = 'x15'
                lobits = 15
            continue

        a, b = xor_pair(word)
        words[i] = a
        xor[i]   = b
	if dst == 'x0':
	    mov_x15 = dst
	    dst = 'x15'
	    lobits = 15

    xor = unpack(b''.join(xor))
    if xor:
        src = unpack(b''.join(words))

tmp = 'x14'
if dst == 'x14':
    tmp = 'x15'
if dst == 'x15':
    tmp = 'x12'

%>
%if src == 'sp':
    add  ${dst}, ${src}, xzr
%elif src == 'x0':
    add  ${dst}, ${src}, xzr, lsl #1
%elif not isinstance(src, six.integer_types):
    mov  ${dst}, ${src}
%else:
  %if src == 0:
    mov  ${dst}, xzr
  %elif src & 0xffff == src:
    mov  ${dst}, #${src}
  %else:
    /* Set ${dst} = ${src} = ${pretty(src, False)} */
    %if src & 0x000000000000ffff:
    mov  ${dst}, #${(src >> 0x00) & 0xffff}
    %else:
    mov  ${dst}, xzr
    %endif
    %if src & 0x00000000ffff0000:
    movk ${dst}, #${(src >> 0x10) & 0xffff}, lsl #16
    %endif
    %if src & 0x0000ffff00000000:
    movk ${dst}, #${(src >> 0x20) & 0xffff}, lsl #0x20
    %endif
    %if src & 0xffff000000000000:
    movk ${dst}, #${(src >> 0x30) & 0xffff}, lsl #0x30
    %endif
  %endif
  %if xor:
  ${SC.mov(tmp, xor)}
  eor ${dst}, ${tmp}, ${dst}
  %endif
  %if mov_x15:
  mov ${mov_x15}, x15
  %endif
%endif
