
<%
    from pwnlib.shellcraft.i386.linux import syscall
%>
<%page args="name"/>
<%docstring>
Invokes the syscall unlink.  See 'man 2 unlink' for more information.

Arguments:
    name(char): name
</%docstring>

    ${syscall('SYS_unlink', name)}
