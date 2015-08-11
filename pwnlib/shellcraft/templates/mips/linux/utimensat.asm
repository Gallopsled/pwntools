
<%
    from pwnlib.shellcraft.mips.linux import syscall
%>
<%page args="fd, path, times, flags"/>
<%docstring>
Invokes the syscall utimensat.  See 'man 2 utimensat' for more information.

Arguments:
    fd(int): fd
    path(char): path
    times(timespec): times
    flags(int): flags
</%docstring>

    ${syscall('SYS_utimensat', fd, path, times, flags)}
