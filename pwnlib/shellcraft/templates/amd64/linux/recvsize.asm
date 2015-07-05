<% from pwnlib.shellcraft import common %>
<% from pwnlib.shellcraft.amd64 import linux %>
<%docstring>
Recives 4 bytes size field
Useful in conjuncion with findpeer and stager
Args:
    sock, the socket to read the payload from.
    reg, the place to put the size (default ecx).
Leaves socket in ebx
</%docstring>
<%page args="sock, reg='rcx'"/>
<%
    recvsize = common.label("recvsize")
%>
${recvsize}:
    xor ${reg}, ${reg}
    push ${reg}
    ${linux.syscall('SYS_read', sock, 'rsp', 4)}
    pop ${reg}
