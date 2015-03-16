<% from pwnlib.shellcraft import common %>
<%page args="dst, src"/>
<%docstring>
    mov(dst, src)

    Returns THUMB code for moving the specified source value
    into the specified destination register.
</%docstring>
%if not isinstance(src, (int, long)):
    mov ${dst}, ${src}
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
