
<%
    from pwnlib.shellcraft.amd64.linux import syscall
%>
<%page args="fd, request, vararg"/>
<%docstring>
Invokes the syscall ioctl.  See 'man 2 ioctl' for more information.

Arguments:
    fd(int): fd
    request(unsigned): request
    vararg(int): vararg
</%docstring>

    ${syscall('SYS_ioctl', fd, request, vararg)}
