<% from pwnlib.shellcraft import amd64 %>
<% from pwnlib.shellcraft import common %>
<%page args="sock=0"/>
<%docstring>
Reads into a buffer of a size and location determined at runtime.
When the shellcode is executing, it should send a pointer and
pointer-width size to determine the location and size of buffer.
</%docstring>
<%
after     = common.label("after")
before    = common.label("before")
%>

${before}:
    /* Read address / size tuples from fd ${sock}, and
       then fill that buffer.  Loop as long as size is nonzero. */
    ${amd64.linux.readptr(sock, 'rsi')}
    push rsi
    ${amd64.linux.readptr(sock, 'rdx')}
    pop rsi
    test rdx, rdx
    jz ${after}
    ${amd64.linux.readn(sock, 'rsi', 'rdx')}
    jmp ${before}
${after}: