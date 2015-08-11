
<%
    from pwnlib.shellcraft.arm.linux import syscall
%>
<%page args="fd, file, tvp"/>
<%docstring>
Invokes the syscall futimesat.  See 'man 2 futimesat' for more information.

Arguments:
    fd(int): fd
    file(char): file
    tvp(timeval): tvp
</%docstring>

    ${syscall('SYS_futimesat', fd, file, tvp)}
