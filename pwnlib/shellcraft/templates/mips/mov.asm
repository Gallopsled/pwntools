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

This might modify the four bytes before the stack pointer.

Args:
  dest (str): The destination register.
  src (str): Either the input register, or an immediate value.
</%docstring>
<%
if not dst in regs:
    log.error('%r is not a register' % str(dst))
    
if not src in regs:
    src = constants.eval(src)

def okay(s):
    return not ('\x00' in s or '\n' in s)

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
        slti ${dst}, $zero, -1
    %elif src == 1:
        slti ${dst}, $zero, 0x0101
    %elif src == -1:
        addi ${dst}, $zero, -1
    %elif src < 0x10000:
        %if okay(packing.pack(src, 16)):
            ori ${dst}, $zero, ${src}
        %else:
            <%
                a, b = fiddling.xor_pair(packing.pack(src, 16), avoid = '\x00\n')
                a = hex(packing.unpack(a, 16))
                b = hex(packing.unpack(b, 16))
            %>\
            ori ${dst}, $zero, ${a}
            xori ${dst}, ${dst}, ${b}
        %endif
    %elif okay(packing.pack(src, 32)):
        lui ${dst}, ${src >> 16}
        ori ${dst}, ${dst}, ${src & 0xffff}
    %else:
        ${mips.mov(dst, src >> 16)}
        sh ${dst}, -4($sp)
        ${mips.mov(dst, src & 0xffff)}
        sh ${dst}, -2($sp)
        lw ${dst}, -4($sp)
    %endif
%endif
