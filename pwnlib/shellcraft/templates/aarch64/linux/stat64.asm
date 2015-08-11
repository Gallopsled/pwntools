
<%
    from pwnlib.shellcraft.aarch64.linux import syscall
%>
<%page args="file, buf"/>
<%docstring>
Invokes the syscall stat64.  See 'man 2 stat64' for more information.

Arguments:
    file(char): file
    buf(stat64): buf
</%docstring>

    ${syscall('SYS_stat64', file, buf)}
