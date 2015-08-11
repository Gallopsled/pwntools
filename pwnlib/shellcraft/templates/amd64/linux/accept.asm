
<%
    from pwnlib.shellcraft.amd64.linux import syscall
%>
<%page args="fd, addr, addr_len"/>
<%docstring>
Invokes the syscall accept.  See 'man 2 accept' for more information.

Arguments:
    fd(int): fd
    addr(SOCKADDR_ARG): addr
    addr_len(socklen_t): addr_len
</%docstring>

    ${syscall('SYS_accept', fd, addr, addr_len)}
