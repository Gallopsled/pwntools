
<%
    from pwnlib.shellcraft.thumb.linux import syscall
%>
<%page args="fd, addr, length"/>
<%docstring>
Invokes the syscall getsockname.  See 'man 2 getsockname' for more information.

Arguments:
    fd(int): fd
    addr(SOCKADDR_ARG): addr
    len(socklen_t): len
</%docstring>

    ${syscall('SYS_getsockname', fd, addr, length)}
