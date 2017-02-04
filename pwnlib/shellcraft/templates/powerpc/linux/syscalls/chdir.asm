
<%
    from pwnlib.shellcraft.powerpc.linux import syscall
%>
<%page args="path"/>
<%docstring>
Invokes the syscall chdir.  See 'man 2 chdir' for more information.

Arguments:
    path(char): path
</%docstring>

    ${syscall('SYS_chdir', path)}
