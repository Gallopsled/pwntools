<%
  from pwnlib.shellcraft import common
  from pwnlib import constants
  from pwnlib.context import context as ctx # Ugly hack, mako will not let it be called context
  from pwnlib.log import getLogger
  from pwnlib.shellcraft.registers import mips as regs
  from pwnlib.util.fiddling import negate, bnot
  log = getLogger('pwnlib.shellcraft.arm.mov')
%>
<%page args="dst, src"/>
<%docstring>
Move src into dest.

Support for automatically avoiding newline and null bytes has to be done.

If src is a string that is not a register, then it will locally set
`context.arch` to `'mips'` and use :func:`pwnlib.constants.eval` to evaluate the
string. Note that this means that this shellcode can change behavior depending
on the value of `context.os`.

Examples:

    >>> print shellcraft.mips.mov('a0','a1').rstrip()
        move $a0, $a1
    >>> print shellcraft.mips.mov('a0', 5).rstrip()
        /* Set r0 = 5 = 0x5 */
        li $a0, 5

Args:
  dest (str): The destination register.
  src (str): Either the input register, or an immediate value.
</%docstring>
<%
if not dst in regs:
    log.error('%r is not a register' % str(dst))

if not src in regs:
    with ctx.local(arch = 'mips'):
        src = constants.eval(src)
%>
%if not isinstance(src, (int, long)):
    move $${dst}, $${src}
%else:
    /* Set ${dst} = ${src} = 0x${'%x' % src} */
  %if src == 0:
    xor $${dst}, $${dst}, $${dst}
  %else:
    li $${dst}, ${src}
  %endif
%endif
