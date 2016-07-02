<%
    from pwnlib.shellcraft.i386.cgc import syscall
%>
<%page args="fd, buf, count, bytes"/>
<%docstring>
Invokes the syscall receive.

For more information, see:
https://github.com/CyberGrandChallenge/libcgc/blob/master/receive.md

Arguments:
    fd(int): fd
    buf(int): buf
    count(int): count
    bytes(int): bytes
</%docstring>

    ${syscall('SYS_receive', fd, buf, count, bytes)}
