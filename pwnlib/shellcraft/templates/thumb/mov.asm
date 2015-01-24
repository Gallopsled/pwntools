<%
  from pwnlib.util import fiddling, packing
  from pwnlib.shellcraft import common, thumb
  from pwnlib import constants
  from pwnlib.context import context as ctx # Ugly hack, mako will not let it be called context
%>
<%page args="dst, src, scrap_register = 'r9'"/>
<%docstring>
    mov(dst, src, scrap_register = 'r9')

    Returns THUMB code for moving the specified source value
    into the specified destination register.

    If src is a string that is not a register, then it will locally set
    `context.arch` to `'thumb'` and use :func:`pwnlib.constants.eval` to evaluate the
    string. Note that this means that this shellcode can change behavior depending
    on the value of `context.os`.

Example:

   >>> print shellcraft.thumb.mov('r1','r2').rstrip()
       mov r1, r2
   >>> print shellcraft.thumb.mov('r1', 0).rstrip()
       eor r1, r1
   >>> print shellcraft.thumb.mov('r1', 10).rstrip()
       eor r1, r1
       add r1, #0x9
       add r1, #1
   >>> print shellcraft.thumb.mov('r1', 17).rstrip()
       eor r1, r1
       add r1, #0x11
   >>> print shellcraft.thumb.mov('r1', 'r1').rstrip()
       /* moving r1 into r1, but this is a no-op */
   >>> print shellcraft.thumb.mov('r1', 0xdead00ff).rstrip()
       eor r1, r1
       add r1, #0xde
       lsl r1, #8
       add r1, #0xad
       lsl r1, #16
       add r1, #0xff
   >>> with context.local(os = 'linux'):
   ...     print shellcraft.thumb.mov('r1', 'SYS_execve').rstrip()
        eor r1, r1
        add r1, #0xb
   >>> with context.local(os = 'freebsd'):
   ...     print shellcraft.thumb.mov('r1', 'SYS_execve').rstrip()
        eor r1, r1
        add r1, #0x3b
   >>> with context.local(os = 'linux'):
   ...     print shellcraft.thumb.mov('r1', 'PROT_READ | PROT_WRITE | PROT_EXEC').rstrip()
       eor r1, r1
       mov r1, #7

</%docstring>
<%
all_regs = ['r' + str(n) for n in range(16)] + ['sp', 'fp', 'pc', 'lr']
src_orig = src
if isinstance(src, (str, unicode)):
    if not '\n' in src:
        src = src.strip()
        if src.lower() in all_regs:
            src = src.lower()
        else:
            with ctx.local(arch = 'thumb'):
                try:
                    src = constants.eval(src)
                except (AttributeError, ValueError):
                    log.error("Could not figure out the value of %r" % src)
                    return
                except (NameError, TypeError):
                    pass
    if isinstance(src, (str, unicode)) and not src in all_regs:
        src = '\x00' * (4 - len(src_orig)) + src_orig
        src = packing.unpack(src, 32, 'little')

%>
% if dst == src:
  /* moving ${src} into ${dst}, but this is a no-op */
% elif not isinstance(src, (int, long)):
    mov ${dst}, ${src}
% else:
  <%
    srcu = src & 0xffffffff
    p = packing.pack(srcu, 32, 'little')
  %>\
  %if srcu == 0:
    eor ${dst}, ${dst}
  %else:
    eor ${dst}, ${dst}
    <%
        to_shift = 0
        count = 4
    %>\
    <% 
        while (srcu >> 24) == 0:
            count -= 1
            srcu <<= 8
    %>\
    % while srcu > 0:
        <%
            count -= 1
            bval = srcu >> 24
            srcu = (srcu << 8) & 0xffffffff
            if bval == 0:
                to_shift += 8
        %>\
        % if bval > 0:
            % if to_shift:
                lsl ${dst}, #${to_shift}
                <%
                    to_shift = 0
                %>\
            % endif
            % if bval == ord('\n'):
                add ${dst}, #0x${'%x' % (bval - 1)}
                add ${dst}, #1
            % else:
                add ${dst}, #0x${'%x' % bval}
            %endif
            <%
                to_shift += 8
            %>\
        %endif
    % endwhile
    % if count > 0:
        lsl ${dst}, #${count * 8}
    % endif
  %endif
%endif
