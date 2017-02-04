
<%
    from pwnlib.shellcraft.mips.linux import syscall
%>
<%page args="fd, buf, n, flags, addr, addr_len"/>
<%docstring>
Invokes the syscall recvfrom.  See 'man 2 recvfrom' for more information.

Arguments:
    fd(int): fd
    buf(void): buf
    n(size_t): n
    flags(int): flags
    addr(SOCKADDR_ARG): addr
    addr_len(socklen_t): addr_len
</%docstring>

    ${syscall('SYS_recvfrom', fd, buf, n, flags, addr, addr_len)}
