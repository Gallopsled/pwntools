
<%
    from pwnlib.shellcraft.amd64.linux import syscall
%>
<%page args="file, buf"/>
<%docstring>
Invokes the syscall lstat64.  See 'man 2 lstat64' for more information.

Arguments:
    file(char): file
    buf(stat64): buf
</%docstring>

    ${syscall('SYS_lstat64', file, buf)}
