
<%
    from pwnlib.shellcraft.powerpc.linux import syscall
%>
<%page args="fd, level, optname, optval, optlen"/>
<%docstring>
Invokes the syscall getsockopt.  See 'man 2 getsockopt' for more information.

Arguments:
    fd(int): fd
    level(int): level
    optname(int): optname
    optval(void): optval
    optlen(socklen_t): optlen
</%docstring>

    ${syscall('SYS_getsockopt', fd, level, optname, optval, optlen)}
