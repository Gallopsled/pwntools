
<%
    from pwnlib.shellcraft.i386.linux import syscall
%>
<%page args="file, buf"/>
<%docstring>
Invokes the syscall stat.  See 'man 2 stat' for more information.

Arguments:
    file(char): file
    buf(stat): buf
</%docstring>

    ${syscall('SYS_stat', file, buf)}
