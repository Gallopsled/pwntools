<%
  from pwnlib.util import lists, packing, fiddling, misc
  from pwnlib.constants import eval, Constant
  from pwnlib.context import context as ctx # Ugly hack, mako will not let it be called context
  from pwnlib.log import getLogger
  from pwnlib.shellcraft import riscv64, registers, pretty, okay
  import six
  log = getLogger('pwnlib.shellcraft.riscv64.mov')
%>
<%page args="dst, src"/>
<%docstring>
Move src into dst without newlines and null bytes.

Registers t4 and t6 are not guaranteed to be preserved.

If src is a string that is not a register, then it will locally set
`context.arch` to `'riscv64'` and use :func:`pwnlib.constants.eval` to evaluate the
string. Note that this means that this shellcode can change behavior depending
on the value of `context.os`.

Args:

  dst (str): The destination register.
  src (str): Either the input register, or an immediate value.

Example:

    >>> print(shellcraft.riscv64.mov('t0', 0).rstrip())
        c.li t0, 0
    >>> print(shellcraft.riscv64.mov('t0', 0x2000).rstrip())
        c.lui t0, 2 /* mv t0, 0x2000 */
    >>> print(shellcraft.riscv64.mov('t5', 0x601).rstrip())
        xori t5, zero, 0x601
    >>> print(shellcraft.riscv64.mov('t5', 0x600).rstrip())
        /* mv t5, 0x600 */
        xori t5, zero, 0x1ff
        xori t5, t5, 0x7ff
    >>> print(shellcraft.riscv64.mov('t6', 0x181f).rstrip())
        /* mv t6, 0x181f */
        lui t6, 0xffffe
        xori t6, t6, 0xfffffffffffff81f
    >>> print(shellcraft.riscv64.mov('t5', 0x40b561f).rstrip())
        /* mv t5, 0x40b561f */
        lui t5, 0x40b5
        xori t5, t5, 0x61f
    >>> print(shellcraft.riscv64.mov('t0', 0xcafebabe).rstrip())
        li t0, 0xcafebabe
    >>> print(shellcraft.riscv64.mov('a0', 't2').rstrip())
        c.mv a0, t2
    >>> print(shellcraft.riscv64.mov('t1', 'sp').rstrip())
        c.mv t6, sp
        c.mv t1, t6 /* mv t1, sp */

</%docstring>
<%
if not isinstance(dst, str) or dst not in registers.riscv:
    log.error("Unknown register %r", dst)
    return

if isinstance(src, str) and src not in registers.riscv:
    src = eval(src)

if isinstance(src, str) and src not in registers.riscv:
    log.error("Unknown register %r", src)
    return

src_reg = registers.riscv.get(src, None)
dst_reg = registers.riscv[dst]
tmp = 't6' if dst_reg != registers.riscv['t6'] else 't4'

# If source register is zero, treat it as immediate 0
if src_reg == 0:
    src = 0
    src_reg = None

encodes_no_newline = lambda a, not_a: not (a & 0xf == 0 or (a & 0xff0) >> 8 in [0, 10]) and not (((not_a & 0xf000) >> 8 | (dst_reg >> 1) in [0, 10]) or (not_a & 0xff0000) >> 16 in [0, 10] or not_a >> 24 in [0, 10])
%>

% if dst_reg == 0 or dst_reg == src_reg:
    /* mv ${dst}, ${src} is a noop */

% elif src_reg is not None:
## Source is a register
## Special case where c.mv would produce a newline
% if src_reg == 2 and dst_reg % 2 == 0:
    c.mv ${tmp}, ${src}
    c.mv ${dst}, ${tmp} /* mv ${dst}, ${src} */
% else:
    c.mv ${dst}, ${src}
% endif
% else:
## Source is an immediate, normalize to [0, 2**64)

<% src = packing.unpack(packing.pack(src, word_size=64), word_size=64, sign=False) %>
## Immediates are always sign-extended to 64-bit

## 6-bit immediate for c.li
% if src < 0x20 or src >= 0xffffffffffffffe0:
    c.li ${dst}, ${pretty(src)}

## 6-bit immediate for c.lui
% elif dst_reg != 2 and src & 0xfff == 0 and ((src>>12) < 0x20 or (src>>12) >= 0xffffffffffffffe0):
    c.lui ${dst}, ${pretty(src>>12)} /* mv ${dst}, ${pretty(src)} */

## 12-bit immediate
% elif src < 0x800 or src >= 0xfffffffffffff800:
    % if src & 0xf == 0 or (src & 0xfff) >> 8 in [0, 10]:
    /* mv ${dst}, ${pretty(src)} */
    xori ${dst}, zero, ${pretty(src ^ 0x7ff)}
    xori ${dst}, ${dst}, ${pretty(0x7ff)}
    % else:
    xori ${dst}, zero, ${pretty(src)}
    % endif

## 32-bit immediate with lui and xori
% elif (src < 0x80000000 or src >= 0xffffffff80000000) and src & 0x800 == 0 and encodes_no_newline(src, src):
    /* mv ${dst}, ${pretty(src)} */
    lui ${dst}, ${pretty(src >> 12)}
    xori ${dst}, ${dst}, ${pretty(src & 0xfff)}
% elif (src < 0x80000000 or src >= 0xffffffff80000000) and src & 0x800 == 0x800 and encodes_no_newline(src, ~src):
    /* mv ${dst}, ${pretty(src)} */
    lui ${dst}, ${pretty((~src >> 12) & 0xfffff)}
    xori ${dst}, ${dst}, ${pretty(src & 0xfff | 0xfffffffffffff000)}

## 64-bit immediate with lui, addi, and slli
## FIXME: Make this null and newline free
% else:
    li ${dst}, ${pretty(src)}

% endif
% endif
