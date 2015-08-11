
<%
    from pwnlib.shellcraft.thumb.linux import syscall
%>
<%page args="fd, cmd, vararg"/>
<%docstring>
Invokes the syscall fcntl.  See 'man 2 fcntl' for more information.

Arguments:
    fd(int): fd
    cmd(int): cmd
    vararg(int): vararg
</%docstring>

    ${syscall('SYS_fcntl', fd, cmd, vararg)}
