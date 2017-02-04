
<%
    from pwnlib.shellcraft.arm.linux import syscall
%>
<%page args=""/>
<%docstring>
Invokes the syscall getppid.  See 'man 2 getppid' for more information.

Arguments:

</%docstring>

    ${syscall('SYS_getppid')}
