
<%
    from pwnlib.shellcraft.aarch64.linux import syscall
%>
<%page args="name"/>
<%docstring>
Invokes the syscall mq_unlink.  See 'man 2 mq_unlink' for more information.

Arguments:
    name(char): name
</%docstring>

    ${syscall('SYS_mq_unlink', name)}
