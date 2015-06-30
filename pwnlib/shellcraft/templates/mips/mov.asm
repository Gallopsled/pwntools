<%
  from pwnlib.util import packing, fiddling
  from pwnlib import constants
  from pwnlib.log import getLogger
  from pwnlib.shellcraft.registers import arm as regs
  from pwnlib.shellcraft import mips
  log = getLogger('pwnlib.shellcraft.arm.mov')
%>
<%page args="dst, src"/>
<%docstring>
Move src into dest.

Args:
  dest (str): The destination register.
  src (str): Either the input register, or an immediate value.
</%docstring>
<%
#if not dst in regs:
#    log.error('%r is not a register' % str(dst))
#    
#if not src in regs:
#    src = constants.eval(src)

%>
.set noat
%if not isinstance(src, (int, long)):
    %if dst == src:
        /* move ${dst}, ${src} is a no-op */
    %else:
        sw ${src}, -4($sp)
        lw ${dst}, -4($sp)
    %endif
%else:
    %if src == 0:
        /* Verified to work for everything except dst=zero */
        slti ${dst}, $zero, -1
    %elif src == -1:
        /* Verified to work for everything except dst=zero */
        addi ${dst}, $zero, -1
    %elif src > 0xffff:
        %if (src & 0xff000000 == 0) or (src & 0xff0000 == 0):
            ;Find out what to do with ${"0x%x" % src}
        %else:
            lui ${dst}, ${src >> 16}
        %endif

        <%
            src &= 0xffff
        %>\
    %endif

    %if src > 0:
        %if (src & 0xff00 == 0) or (src & 0xff == 0):
            <%
                a, b = fiddling.xor_pair(packing.pack(src, 16), avoid = '\x00\n')
                a = hex(packing.unpack(a, 16))
                b = hex(packing.unpack(b, 16))
            %>\
            ori ${dst}, $zero, ${a}
            xori ${dst}, ${dst}, ${b}
        %else:
            /* Verified to work for everything except dst=zero */
            ori ${dst}, $zero, ${src}
        %endif
    %endif
%endif
