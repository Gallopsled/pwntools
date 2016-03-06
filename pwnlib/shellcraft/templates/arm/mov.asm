<%
  from pwnlib.shellcraft import common
  from pwnlib import constants
  from pwnlib.context import context as ctx # Ugly hack, mako will not let it be called context
  from pwnlib.log import getLogger
  from pwnlib.shellcraft.registers import arm as regs
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

    >>> print shellcraft.arm.mov('r0','r1').rstrip()
        mov r0, r1
    >>> print shellcraft.arm.mov('r0', 5).rstrip()
        /* Set r0 = 5 = 0x5 */
        mov r0, #5
    >>> print shellcraft.arm.mov('r0', '0x34532').rstrip()
        /* Set r0 = 214322 = 0x34532 */
        movw r0, #17714
        movt r0, #3

Args:
  dest (str): The destination register.
  src (str): Either the input register, or an immediate value.
</%docstring>
<%
if not dst in regs:
    log.error('%r is not a register' % str(dst))
    
if not src in regs:
    with ctx.local(arch = 'arm'):
        src = constants.eval(src)

%>
%if not isinstance(src, (int, long)):
    %if dst == src:
    /* mov %{dest}, ${src} is a no-op */
    %else:
    mov ${dst}, ${src}
    %endif
%else:
    /* Set ${dst} = ${src} = 0x${'%x' % src} */
  %if src == 0:
    eor ${dst}, ${dst}
  %elif src & 0xffff0000 == 0:
    mov ${dst}, #${src}
  %else:
    movw ${dst}, #${src & 0xffff}
    movt ${dst}, #${src >> 16}
  %endif
%endif
