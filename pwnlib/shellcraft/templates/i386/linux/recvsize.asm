<% from pwnlib.shellcraft import common %>
<% from pwnlib.shellcraft import i386 %>
<%docstring>
Recives 4 bytes size field
Useful in conjuncion with findpeer and stager
Args:
    sock, the socket to read the payload from.
    reg, the place to put the size (default ecx).
Leaves socket in ebx
</%docstring>
<%page args="sock, reg='ecx'"/>
<%
    recvsize = common.label("recvsize")
%>
${recvsize}:
    ${i386.linux.syscall('SYS_read', sock, 'esp', 4)}
    pop ${reg}
