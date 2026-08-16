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

Args:

  dst (str): The destination register.
  src (str): Either the input register, or an immediate value.

Example:

    >>> print(shellcraft.loongarch64.mov('t0', 0).rstrip())
        li.d     $t0, 0
    >>> print(shellcraft.loongarch64.mov('t0', 0x2000).rstrip())
        li.d     $t0, 8192
    >>> print(shellcraft.loongarch64.mov('t0', 0xcafebabe).rstrip())
        li.d     $t0, 3405691582
    >>> print(shellcraft.loongarch64.mov('t1', 'sp').rstrip())
        move     $t1, $sp

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
    /* mov ${dst}, ${src} is a noop */
% elif src_reg is not None:
    move     $${dst}, $${src}
% else:
## Source is an immediate, normalize to [0, 2**64)
<% src = packing.unpack(packing.pack(src, word_size=64), word_size=64, sign=False) %>
## Immediates are always sign-extended to 64-bit
    li.d     $${dst}, ${src}
% endif
