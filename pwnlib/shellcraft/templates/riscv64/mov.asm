<%
  from pwnlib.util import lists, packing, fiddling, misc
  from pwnlib.constants import eval, Constant
  from pwnlib.context import context as ctx # Ugly hack, mako will not let it be called context
  from pwnlib.log import getLogger
  from pwnlib.shellcraft import riscv64, registers, pretty, okay
  log = getLogger('pwnlib.shellcraft.riscv64.mov')
%>
<%page args="dst, src, c=False"/>
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
        xor t0, t6, t6
    >>> print(shellcraft.riscv64.mov('t0', 0x2000, c=True).rstrip())
        c.lui t0, 0xfffff & (0x2000 >> 12)
    >>> print(shellcraft.riscv64.mov('t5', 0x601).rstrip())
        xori t5, zero, 0x601
    >>> print(shellcraft.riscv64.mov('t5', 0x600).rstrip())
        xori t5, zero, 0x7ff ^ 0x600
        xori t5, t5, 0x7ff
    >>> print(shellcraft.riscv64.mov('t6', 0x181f).rstrip())
        lui t6, 0xfffff & (~0x181f >> 12)
        xori t6, t6, ~0x7ff | 0x181f
    >>> print(shellcraft.riscv64.mov('t5', 0x40b561f).rstrip())
        lui t5, 0xfffff & (0x40b561f >> 12)
        xori t5, t5, 0x7ff & 0x40b561f
    >>> print(shellcraft.riscv64.mov('t0', 0xcafebabe).rstrip())
        li t0, 0xcafebabe
    >>> print(shellcraft.riscv64.mov('a0', 't2', c=True).rstrip())
        c.mv a0, t2
    >>> print(shellcraft.riscv64.mov('t1', 'sp', c=True).rstrip())
        sra t1, sp, zero

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
%  if c and not (src_reg == 2 and dst_reg % 2 == 0):
    c.mv ${dst}, ${src}
%  elif (src_reg >> 1) not in (0, 10):
    sra ${dst}, ${src}, zero
%  else:
    not ${dst}, ${src}
    not ${dst}, ${dst}
%  endif
% else:
## Source is an immediate, normalize to [0, 2**64)

<% srcn = src & 0xffffffffffffffff %>
## Immediates are always sign-extended to 64-bit

## 6-bit immediate for c.li
% if c and (srcn < 0x20 or srcn >= 0xffffffffffffffe0):

    c.li ${dst}, ${pretty(src)}
## 6-bit immediate for c.lui
% elif c and (dst_reg != 2 and srcn & 0xfff == 0 and ((srcn>>12) < 0x20 or (srcn>>12) >= 0xffffffffffffffe0)):
    c.lui ${dst}, 0xfffff & (${pretty(src)} >> 12)
## 12-bit immediate
% elif srcn < 0x800 or srcn >= 0xfffffffffffff800:
    % if srcn == 0:
    xor ${dst}, t6, t6
    % elif srcn == 1:
    sltiu ${dst}, zero, 0x7ff | ${pretty(src)}
    % elif src & 0xf == 0 or (src & 0xfff) >> 8 in [0, 10]:
    xori ${dst}, zero, 0x7ff ^ ${pretty(src)}
    xori ${dst}, ${dst}, 0x7ff
    % else:
    xori ${dst}, zero, ${pretty(src)}
    % endif

## 32-bit immediate with lui and xori
% elif (srcn < 0x80000000 or srcn >= 0xffffffff80000000) and srcn & 0x800 == 0 and encodes_no_newline(srcn, srcn):
    lui ${dst}, 0xfffff & (${pretty(src)} >> 12)
    xori ${dst}, ${dst}, 0x7ff & ${pretty(src)}
% elif (srcn < 0x80000000 or srcn >= 0xffffffff80000000) and srcn & 0x800 == 0x800 and encodes_no_newline(srcn, srcn + 0x800):
    lui ${dst}, 0xfffff & ((${pretty(src)} >> 12) + 1)
    xori ${dst}, ${dst}, 0x7ff & ${pretty(src)}
    addi ${dst}, ${dst}, -0x800
% elif (srcn < 0x80000000 or srcn >= 0xffffffff80000000) and encodes_no_newline(srcn, ~srcn):
    lui ${dst}, 0xfffff & (~${pretty(src)} >> 12)
    xori ${dst}, ${dst}, ~0x7ff | ${pretty(src)}
    % if not srcn & 0x800:
    addi ${dst}, ${dst}, -0x800
    % endif

## 64-bit immediate with lui, addi, and slli
% elif srcn > 0xfffffffff and srcn < 0xffffffff00000000:
    % if src & 0x80000000:
    ${riscv64.mov(dst, ~src >> 32)}
    ${riscv64.mov('t6', src | ~0x7fffffff)}
    % else:
    ${riscv64.mov(dst, src >> 32)}
    ${riscv64.mov('t6', src & 0x7fffffff)}
    % endif
    slli ${dst}, ${dst}, 0x20
    xor ${dst}, ${dst}, t6
% else:
## FIXME: Make this null and newline free
    li ${dst}, ${pretty(src)}

% endif
% endif
