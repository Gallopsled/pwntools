
<%
    from pwnlib.shellcraft.powerpc.linux import syscall
%>
<%page args="fd, file, mode, flag"/>
<%docstring>
Invokes the syscall fchmodat.  See 'man 2 fchmodat' for more information.

Arguments:
    fd(int): fd
    file(char): file
    mode(mode_t): mode
    flag(int): flag
</%docstring>

    ${syscall('SYS_fchmodat', fd, file, mode, flag)}
