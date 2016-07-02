
<%
    from pwnlib.shellcraft.i386.linux import syscall
%>
<%page args="path"/>
<%docstring>
Invokes the syscall rmdir.  See 'man 2 rmdir' for more information.

Arguments:
    path(char): path
</%docstring>

    ${syscall('SYS_rmdir', path)}
