
<%
    from pwnlib.shellcraft.amd64.linux import syscall
%>
<%page args="file, mode"/>
<%docstring>
Invokes the syscall creat.  See 'man 2 creat' for more information.

Arguments:
    file(char): file
    mode(mode_t): mode
</%docstring>

    ${syscall('SYS_creat', file, mode)}
