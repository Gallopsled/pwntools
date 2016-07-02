
<%
    from pwnlib.shellcraft.arm.linux import syscall
%>
<%page args="fd, fd2"/>
<%docstring>
Invokes the syscall dup2.  See 'man 2 dup2' for more information.

Arguments:
    fd(int): fd
    fd2(int): fd2
</%docstring>

    ${syscall('SYS_dup2', fd, fd2)}
