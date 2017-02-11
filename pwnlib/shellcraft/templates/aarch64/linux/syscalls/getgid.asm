
<%
    from pwnlib.shellcraft.aarch64.linux import syscall
%>
<%page args=""/>
<%docstring>
Invokes the syscall getgid.  See 'man 2 getgid' for more information.

Arguments:

</%docstring>

    ${syscall('SYS_getgid')}
