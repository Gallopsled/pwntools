
<%
    from pwnlib.shellcraft.aarch64.linux import syscall
%>
<%page args="file, mode"/>
<%docstring>
Invokes the syscall chmod.  See 'man 2 chmod' for more information.

Arguments:
    file(char): file
    mode(mode_t): mode
</%docstring>

    ${syscall('SYS_chmod', file, mode)}
