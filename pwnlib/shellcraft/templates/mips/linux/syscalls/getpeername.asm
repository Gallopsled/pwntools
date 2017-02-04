
<%
    from pwnlib.shellcraft.mips.linux import syscall
%>
<%page args="fd, addr, length"/>
<%docstring>
Invokes the syscall getpeername.  See 'man 2 getpeername' for more information.

Arguments:
    fd(int): fd
    addr(SOCKADDR_ARG): addr
    len(socklen_t): len
</%docstring>

    ${syscall('SYS_getpeername', fd, addr, length)}
