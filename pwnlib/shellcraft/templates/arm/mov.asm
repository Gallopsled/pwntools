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
  %if (src & 0xffff0000) == 0 or (src & 0xffff) == 0:
    eor ${dst}, ${dst}
  %endif
  %if src & 0xffff0000:
    movt ${dst}, #${src >> 16}
  %endif
  %if src & 0xffff:
    movw ${dst}, #${src & 0xffff}
  %endif
%endif
