
<%
    from pwnlib.shellcraft.powerpc.linux import syscall
%>
<%page args="fd, addr, length"/>
<%docstring>
Invokes the syscall connect.  See 'man 2 connect' for more information.

Arguments:
    fd(int): fd
    addr(CONST_SOCKADDR_ARG): addr
    len(socklen_t): len
</%docstring>

    ${syscall('SYS_connect', fd, addr, length)}
