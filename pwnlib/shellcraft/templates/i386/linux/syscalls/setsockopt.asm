
<%
    from pwnlib.shellcraft.i386.linux import syscall
    from pwnlib.shellcraft.i386 import push
    from pwnlib.constants import SOCK_STREAM, AF_INET, SYS_socketcall, SYS_socketcall_setsockopt
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
	${push(optlen)}
	${push(optval)}
	${push(optname)}
	${push(level)}
	${push(sockfd)}
	${syscall(SYS_socketcall, SYS_socketcall_setsockopt, 'esp', 0)}

