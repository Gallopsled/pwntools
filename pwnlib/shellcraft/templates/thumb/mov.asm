<% from pwnlib.shellcraft import common %>
<%page args="dst, src"/>
<%docstring>
    mov(dst, src)

    Returns THUMB code for moving the specified source value
    into the specified destination register.
</%docstring>
/* Set ${dst} = ${src} */
%if not isinstance(src, (int, long)):
    mov ${dst}, ${src}
%else:
  <%
    srcu = src & 0xffffffff
    srcs = srcu - 2 * (srcu & 0x80000000)
  %>
  %if srcu == 0:
    eor ${dst}, ${dst}
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
    %>
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
      %>
      %if ((0xff << shift2) | 0xff) & src == src:
        mov ${dst}, #${src >> shift2}
        lsl ${dst}, #${shift2}
        add ${dst}, #${src & 0xff}
      %else:
        <%
          shift3 = shift1 + 8
          while (1 << shift3) & src == 0:
              shift3 += 1
        %>
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
                  extra = '\n'.join([
                    "lsl %s, #8" % dst,
                    "lsr %s, #8" % dst
                  ])
            %>
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
