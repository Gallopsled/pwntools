
<%
    from pwnlib.shellcraft.amd64.linux import syscall
%>
<%page args="fd"/>
<%docstring>
Invokes the syscall fsync.  See 'man 2 fsync' for more information.

Arguments:
    fd(int): fd
</%docstring>

    ${syscall('SYS_fsync', fd)}
