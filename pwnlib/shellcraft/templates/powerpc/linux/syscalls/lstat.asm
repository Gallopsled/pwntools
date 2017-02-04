
<%
    from pwnlib.shellcraft.powerpc.linux import syscall
%>
<%page args="file, buf"/>
<%docstring>
Invokes the syscall lstat.  See 'man 2 lstat' for more information.

Arguments:
    file(char): file
    buf(stat): buf
</%docstring>

    ${syscall('SYS_lstat', file, buf)}
