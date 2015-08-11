
<%
    from pwnlib.shellcraft.amd64.linux import syscall
%>
<%page args="fd, offset, count, flags"/>
<%docstring>
Invokes the syscall sync_file_range.  See 'man 2 sync_file_range' for more information.

Arguments:
    fd(int): fd
    offset(off64_t): offset
    count(off64_t): count
    flags(unsigned): flags
</%docstring>

    ${syscall('SYS_sync_file_range', fd, offset, count, flags)}
