<%
  from pwnlib.util import lists, packing, fiddling, misc
  from pwnlib.constants import eval, Constant
  from pwnlib.context import context as ctx # Ugly hack, mako will not let it be called context
  from pwnlib.log import getLogger
  from pwnlib.shellcraft import loongarch64, registers, pretty, okay
  log = getLogger('pwnlib.shellcraft.loongarch64.mov')
%>
<%page args="dst, src"/>
<%docstring>
Move src into dst.

If src is a string that is not a register, then it will locally set
`context.arch` to `'loongarch64'` and use :func:`pwnlib.constants.eval` to evaluate the
string. Note that this means that this shellcode can change behavior depending
on the value of `context.os`.

There is no effort done to avoid newlines and null bytes in the generated code.

Args:

  dst (str): The destination register.
  src (str): Either the input register, or an immediate value.

Example:

    >>> print(shellcraft.loongarch64.mov('t0', 0).rstrip())
        addi.d   $t0, $r0, 0
    >>> print(shellcraft.loongarch64.mov('t0', 0x2000).rstrip())
        addi.d   $t0, $r0, 2
        lu52i.d  $t0, $t0, 0
    >>> print(shellcraft.loongarch64.mov('t0', 0xcafebabe).rstrip())
        addi.d   $t0, $r0, 202
        lu52i.d  $t0, $t0, -21
        lu52i.d  $t0, $t0, -1346
    >>> print(shellcraft.loongarch64.mov('t1', 'sp').rstrip())
        addi.d   $t1, $sp, 0

</%docstring>
<%
if not isinstance(dst, str) or dst not in registers.loongarch64:
    log.error("Unknown register %r", dst)
    return

if isinstance(src, str) and src not in registers.loongarch64:
    src = eval(src)

if isinstance(src, str) and src not in registers.loongarch64:
    log.error("Unknown register %r", src)
    return

src_reg = registers.loongarch64.get(src, None)
dst_reg = registers.loongarch64[dst]

# If source register is zero, treat it as immediate 0
if src_reg == 0:
    src = 0
    src_reg = None
%>

% if dst_reg == 0 or dst_reg == src_reg:
    /* ld ${dst}, ${src} is a noop */
% elif src_reg is not None:
    addi.d   $${dst}, $${src}, 0
% else:
## Source is an immediate, normalize to [0, 2**64)

<% src = packing.unpack(packing.pack(src, word_size=64), word_size=64, sign=False) %>
## Immediates are always sign-extended to 64-bit

% if src == 0:
    addi.d   $${dst}, $r0, 0
% else:
<%
parts = []
fullsrc = src
while src != 0:
    parts.append(packing.unpack(packing.pack((src & 0xfff), word_size=12, sign=False), word_size=12, sign=True))
    src = src >> 12
%>
% for idx, part in enumerate(reversed(parts)):
    % if idx == 0:
    addi.d   $${dst}, $r0, ${part}
    % else:
    lu52i.d  $${dst}, $${dst}, ${part}
    % endif
% endfor
% endif
% endif
