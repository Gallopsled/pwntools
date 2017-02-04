
<%
    from pwnlib.shellcraft.aarch64.linux import syscall
%>
<%page args=""/>
<%docstring>
Invokes the syscall geteuid.  See 'man 2 geteuid' for more information.

Arguments:

</%docstring>

    ${syscall('SYS_geteuid')}
