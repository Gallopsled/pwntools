
<%
    from pwnlib.shellcraft.arm.linux import syscall
    from pwnlib.shellcraft.arm import push
%>
<%page args="sockfd, level, optname, optval, optlen"/>
<%docstring>
Invokes the syscall setsockopt.  See 'man 2 setsockopt' for more information.

Arguments:
    sockfd(int): sockfd
    level(int): level
    optname(int): optname
    optval(void): optval
    optlen(int): optlen
</%docstring>
	${syscall('SYS_setsockopt', sockfd, level, optname, optval, optlen)}

