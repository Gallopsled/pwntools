
<%
    from pwnlib.shellcraft.arm.linux import syscall
%>
<%page args="fd, buf"/>
<%docstring>
Invokes the syscall fstat.  See 'man 2 fstat' for more information.

Arguments:
    fd(int): fd
    buf(stat): buf
</%docstring>

    ${syscall('SYS_fstat', fd, buf)}
