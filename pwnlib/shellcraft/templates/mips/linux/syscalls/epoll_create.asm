
<%
    from pwnlib.shellcraft.mips.linux import syscall
%>
<%page args="size"/>
<%docstring>
Invokes the syscall epoll_create.  See 'man 2 epoll_create' for more information.

Arguments:
    size(int): size
</%docstring>

    ${syscall('SYS_epoll_create', size)}
