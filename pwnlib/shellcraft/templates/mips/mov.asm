<%
  from pwnlib.util import packing, fiddling
  from pwnlib import constants
  from pwnlib.log import getLogger
  from pwnlib.shellcraft.registers import mips as regs
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
if not dst in regs:
    log.error('%r is not a register' % str(dst))
    
#if not src in regs:
#    src = constants.eval(src)

%>
.set noat
%if not isinstance(src, (int, long)):
    %if dst == src:
        /* move ${dst}, ${src} is a no-op */
    %else:
        /* Verified to not generate nul bytes */
        sw ${src}, -4($sp)
        lw ${dst}, -4($sp)
    %endif
%else:
    %if src == 0:
        /* Verified to not generate nul bytes */
        slti ${dst}, $zero, -1
    %elif src == 1:
        /* Verified to not generate nul bytes */
        slti ${dst}, $zero, 0x0101
    %elif src == -1:
        /* Verified to not generate nul bytes */
        addi ${dst}, $zero, -1
    %elif src < 0x10000:
        %if src & 0xff00 == 0 or src & 0x00ff == 0:
            /* Verified to not generate nul bytes */
            <%
                a, b = fiddling.xor_pair(packing.pack(src, 16), avoid = '\x00\n')
                a = hex(packing.unpack(a, 16))
                b = hex(packing.unpack(b, 16))
            %>\
            ori ${dst}, $zero, ${a}
            xori ${dst}, ${dst}, ${b}
        %else:
            /* Verified to not generate nul bytes */
            ori ${dst}, $zero, ${src}
        %endif
    %elif not '\x00' in packing.pack(src, 32):
        /* Verified to not generate nul bytes */
        lui ${dst}, ${src >> 16}
        ori ${dst}, ${dst}, ${src & 0xffff}
    %else:
        /* Verified to not generate nul bytes */
        ${mips.mov(dst, src >> 16)}
        sh ${dst}, -4($sp)
        ${mips.mov(dst, src & 0xffff)}
        sh ${dst}, -2($sp)
        lw ${dst}, -4($sp)
    %endif
%endif
