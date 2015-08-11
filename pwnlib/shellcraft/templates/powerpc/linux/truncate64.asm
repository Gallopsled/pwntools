
<%
    from pwnlib.shellcraft.powerpc.linux import syscall
%>
<%page args="file, length"/>
<%docstring>
Invokes the syscall truncate64.  See 'man 2 truncate64' for more information.

Arguments:
    file(char): file
    length(off64_t): length
</%docstring>

    ${syscall('SYS_truncate64', file, length)}
