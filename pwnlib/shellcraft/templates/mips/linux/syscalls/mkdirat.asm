
<%
    from pwnlib.shellcraft.mips.linux import syscall
%>
<%page args="fd, path, mode"/>
<%docstring>
Invokes the syscall mkdirat.  See 'man 2 mkdirat' for more information.

Arguments:
    fd(int): fd
    path(char): path
    mode(mode_t): mode
</%docstring>

    ${syscall('SYS_mkdirat', fd, path, mode)}
