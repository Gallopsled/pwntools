
<%
    from pwnlib.shellcraft.arm.linux import syscall
%>
<%page args="mask"/>
<%docstring>
Invokes the syscall umask.  See 'man 2 umask' for more information.

Arguments:
    mask(mode_t): mask
</%docstring>

    ${syscall('SYS_umask', mask)}
