
<%
    from pwnlib.shellcraft.aarch64.linux import syscall
%>
<%page args="fd, fd2, flags"/>
<%docstring>
Invokes the syscall dup3.  See 'man 2 dup3' for more information.

Arguments:
    fd(int): fd
    fd2(int): fd2
    flags(int): flags
</%docstring>

    ${syscall('SYS_dup3', fd, fd2, flags)}
