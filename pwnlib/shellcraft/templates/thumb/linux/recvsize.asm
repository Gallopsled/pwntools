<% from pwnlib.shellcraft import common %>
<% from pwnlib.shellcraft.thumb import linux %>
<%docstring>
Recives 4 bytes size field
Useful in conjuncion with findpeer and stager
Args:
    sock, the socket to read the payload from.
    reg, the place to put the size (default ecx).
Leaves socket in ebx
</%docstring>
<%page args="sock, reg='r1'"/>
<%
    recvsize = common.label("recvsize")
%>
${recvsize}:
    ${linux.syscall('SYS_read', sock, 'sp', 4)}
    pop {${reg}}
