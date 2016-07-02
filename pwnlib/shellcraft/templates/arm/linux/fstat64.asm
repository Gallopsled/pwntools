
<%
    from pwnlib.shellcraft.arm.linux import syscall
%>
<%page args="fd, buf"/>
<%docstring>
Invokes the syscall fstat64.  See 'man 2 fstat64' for more information.

Arguments:
    fd(int): fd
    buf(stat64): buf
</%docstring>

    ${syscall('SYS_fstat64', fd, buf)}
