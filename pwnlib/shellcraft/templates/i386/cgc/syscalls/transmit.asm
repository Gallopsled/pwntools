<%
    from pwnlib.shellcraft.i386.cgc import syscall
%>
<%page args="fd, buf, count, tx_bytes"/>
<%docstring>
Invokes the syscall transmit.

For more information, see:
https://github.com/CyberGrandChallenge/libcgc/blob/master/transmit.md

Arguments:
    fd(int): fd
    buf(int): buf
    count(int): count
    tx_bytes(int): tx_bytes
</%docstring>

    ${syscall('SYS_transmit', fd, buf, count, tx_bytes)}
