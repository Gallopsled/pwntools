<%
  from pwnlib.shellcraft import common
  from pwnlib import constants
  from pwnlib.context import context as ctx # Ugly hack, mako will not let it be called context
%>
<%page args="dst, src"/>
<%docstring>
    mov(dst, src)

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
       mov r1, #10
   >>> print shellcraft.thumb.mov('r1', 17).rstrip()
       mov r1, #17
   >>> print shellcraft.thumb.mov('r1', 'r1').rstrip()
       /* moving r1 into r1, but this is a no-op */
   >>> print shellcraft.thumb.mov('r1', 0xdead00ff).rstrip()
       ldr r1, value_...
       b value_..._after
   value_...: .word 3735879935
   value_..._after:
   >>> with context.local(os = 'linux'):
   ...     print shellcraft.thumb.mov('r1', 'SYS_execve').rstrip()
       mov r1, #SYS_execve
   >>> with context.local(os = 'freebsd'):
   ...     print shellcraft.thumb.mov('r1', 'SYS_execve').rstrip()
       mov r1, #SYS_execve
   >>> with context.local(os = 'linux'):
   ...     print shellcraft.thumb.mov('r1', 'PROT_READ | PROT_WRITE | PROT_EXEC').rstrip()
       mov r1, #7

</%docstring>
<%
all_regs = ['r' + str(n) for n in range(16)] + ['sp', 'fp', 'pc', 'lr']
src_orig = src
if isinstance(src, (str, unicode)):
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

%>
% if dst == src:
  /* moving ${src} into ${dst}, but this is a no-op */
% elif not isinstance(src, (int, long)):
    mov ${dst}, ${src}
% else:
  <%
    srcu = src & 0xffffffff
    srcs = srcu - 2 * (srcu & 0x80000000)
  %>\
  %if srcu == 0:
    %if dst == 'r0':
        movs r0, 1
        subs r0, 1
    %else:
        eor ${dst}, ${dst}
    %endif
  %elif srcu < 256:
    mov ${dst}, #${src}
  %elif -256 < srcs < 0:
    eor ${dst}, ${dst}
    sub ${dst}, #${-srcs}
  %else:
    <%
      shift1 = 0
      while (1 << shift1) & src == 0:
          shift1 += 1
    %>\
    %if (0xff << shift1) & src == src:
      %if shift1 < 4:
        mov ${dst}, #${src >> shift1}
        lsl ${dst}, #4
        lsr ${dst}, #{4 - shift1}
      %else:
        mov ${dst}, #${src >> shift1}
        lsl ${dst}, #${shift1}
      %endif
    %else:
      <%
        shift2 = 8
        while (1 << shift2) & src == 0:
            shift2 += 1
      %>\
      %if ((0xff << shift2) | 0xff) & src == src:
        mov ${dst}, #${src >> shift2}
        lsl ${dst}, #${shift2}
        add ${dst}, #${src & 0xff}
      %else:
        <%
          shift3 = shift1 + 8
          while (1 << shift3) & src == 0:
              shift3 += 1
        %>\
        %if ((0xff << shift1) | (0xff << shift3)) & src == src:
          mov ${dst}, #${src >> shift3}
          lsl ${dst}, #${shift3 - shift1}
          add ${dst}, #${(src >> shift1) & 0xff}
          lsl ${dst}, #${shift1}
        %else:
            <%
              id = common.label("value")
              extra = ''
              if (src & 0xff000000 == 0):
                  src = src | 0xff000000
                  extra = '\n '.join([
                    "lsl %s, #8" % dst,
                    "lsr %s, #8" % dst
                  ])
            %>\
            ldr ${dst}, ${id}
            b ${id}_after
            ${id}: .word ${src}
            ${id}_after:
            ${extra}
        %endif
      %endif
    %endif
  %endif
%endif
