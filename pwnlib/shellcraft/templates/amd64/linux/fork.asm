
<%
    from pwnlib.shellcraft.amd64.linux import syscall
%>
<%page args=""/>
<%docstring>
Invokes the syscall fork.  See 'man 2 fork' for more information.

Arguments:

</%docstring>

    ${syscall('SYS_fork')}
