<%
  from pwnlib.shellcraft import common, eval, pretty, okay
  from pwnlib.constants import Constant
  from pwnlib.log import getLogger
  from pwnlib.shellcraft.registers import arm as regs
  from pwnlib.util import fiddling
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

    >>> print(shellcraft.arm.mov('r0','r1').rstrip())
        mov  r0, r1
    >>> print(shellcraft.arm.mov('r0', 5).rstrip())
        mov  r0, #5
    >>> print(shellcraft.arm.mov('r0', 0x34532).rstrip())
        movw r0, #0x34532 & 0xffff
        movt r0, #0x34532 >> 16
    >>> print(shellcraft.arm.mov('r0', 0x101).rstrip())
        movw r0, #0x101
    >>> print(shellcraft.arm.mov('r0', 0xff << 14).rstrip())
        mov  r0, #0x3fc000
    >>> print(shellcraft.arm.mov('r0', 0xff << 15).rstrip())
        movw r0, #0x7f8000 & 0xffff
        movt r0, #0x7f8000 >> 16
    >>> print(shellcraft.arm.mov('r0', 0xf00d0000).rstrip())
        eor  r0, r0
        movt r0, #0xf00d0000 >> 16
    >>> print(shellcraft.arm.mov('r0', 0xffff00ff).rstrip())
        mvn  r0, #(0xffff00ff ^ (-1))
    >>> print(shellcraft.arm.mov('r0', 0x1fffffff).rstrip())
        mvn  r0, #(0x1fffffff ^ (-1))

Args:
  dest (str): ke destination register.
  src (str): Either the input register, or an immediate value.
</%docstring>
<%
if not dst in regs:
    log.error('%r is not a register' % str(dst))


# ARM has a mov-const-with-shift
# As long as the const fits in 8 bits, everything works out :)
def get_imm8_shift_ok(v):
    v_bits = fiddling.bits(v)
    retval = 0

    if v == 0:
        return 1

    trailing_zeroes = v_bits[::-1].index(1)
    leading_zeroes  = v_bits.index(1)
    width           = len(v_bits) - leading_zeroes - trailing_zeroes

    if width > 8:
      return 0

    retval = v >> trailing_zeroes

    if width > 8 \
    or not okay(retval, bits=8) \
    or (width == 8 and 0 != (trailing_zeroes % 2)):
        return 0

    return retval

if not src in regs:
    src = eval(src)
    srcu = src & 0xffffffff
    srcn = fiddling.negate(src + 1)
    positive_imm8_shift = get_imm8_shift_ok(srcu)
    negative_imm8_shift = get_imm8_shift_ok(srcn)

%>
%if src == dst:
    /* mov ${dst}, ${src} */
%elif not isinstance(src, (int, long)):
    mov  ${dst}, ${src}
%else:
    %if src == 0:
    eor  ${dst}, ${dst} /* ${src} (${'#%x' % src}) */
    %elif positive_imm8_shift:
    mov  ${dst}, #${pretty(src)}
    %elif src & 0x0000ffff == src:
    movw ${dst}, #${pretty(src)}
    %elif negative_imm8_shift:
    mvn  ${dst}, #(${pretty(src)} ^ (-1))
    %elif src > 0 and srcu & 0xffff0000 == src:
    eor  ${dst}, ${dst}
    movt ${dst}, #${pretty(src)} >> 16
    %elif src > 0:
    movw ${dst}, #${pretty(src)} & 0xffff
    movt ${dst}, #${pretty(src)} >> 16
    %else:
    movw ${dst}, #${pretty(src)} >> 00 & 0xffff
    movt ${dst}, #${pretty(src)} >> 16 & 0xffff
    %endif
%endif
