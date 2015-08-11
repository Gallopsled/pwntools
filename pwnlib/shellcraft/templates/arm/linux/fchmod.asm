
<%
    from pwnlib.shellcraft.arm.linux import syscall
%>
<%page args="fd, mode"/>
<%docstring>
Invokes the syscall fchmod.  See 'man 2 fchmod' for more information.

Arguments:
    fd(int): fd
    mode(mode_t): mode
</%docstring>

    ${syscall('SYS_fchmod', fd, mode)}
