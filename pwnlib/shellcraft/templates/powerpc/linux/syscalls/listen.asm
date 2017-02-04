
<%
    from pwnlib.shellcraft.powerpc.linux import syscall
%>
<%page args="fd, n"/>
<%docstring>
Invokes the syscall listen.  See 'man 2 listen' for more information.

Arguments:
    fd(int): fd
    n(int): n
</%docstring>

    ${syscall('SYS_listen', fd, n)}
