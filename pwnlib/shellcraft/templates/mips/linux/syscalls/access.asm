
<%
    from pwnlib.shellcraft.mips.linux import syscall
%>
<%page args="name, type"/>
<%docstring>
Invokes the syscall access.  See 'man 2 access' for more information.

Arguments:
    name(char): name
    type(int): type
</%docstring>

    ${syscall('SYS_access', name, type)}
