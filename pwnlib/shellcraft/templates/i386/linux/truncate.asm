
<%
    from pwnlib.shellcraft.i386.linux import syscall
%>
<%page args="file, length"/>
<%docstring>
Invokes the syscall truncate.  See 'man 2 truncate' for more information.

Arguments:
    file(char): file
    length(off_t): length
</%docstring>

    ${syscall('SYS_truncate', file, length)}
