
<%
    from pwnlib.shellcraft.amd64.linux import syscall
%>
<%page args="level"/>
<%docstring>
Invokes the syscall iopl.  See 'man 2 iopl' for more information.

Arguments:
    level(int): level
</%docstring>

    ${syscall('SYS_iopl', level)}
