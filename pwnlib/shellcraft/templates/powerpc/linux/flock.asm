
<%
    from pwnlib.shellcraft.powerpc.linux import syscall
%>
<%page args="fd, operation"/>
<%docstring>
Invokes the syscall flock.  See 'man 2 flock' for more information.

Arguments:
    fd(int): fd
    operation(int): operation
</%docstring>

    ${syscall('SYS_flock', fd, operation)}
