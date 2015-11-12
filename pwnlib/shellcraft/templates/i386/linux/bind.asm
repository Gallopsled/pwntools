
<%
    from pwnlib.shellcraft.i386.linux import syscall
%>
<%page args="fd, addr, length"/>
<%docstring>
Invokes the syscall bind.  See 'man 2 bind' for more information.

Arguments:
    fd(int): fd
    addr(CONST_SOCKADDR_ARG): addr
    len(socklen_t): len
</%docstring>

    ${syscall('SYS_bind', fd, addr, length)}
