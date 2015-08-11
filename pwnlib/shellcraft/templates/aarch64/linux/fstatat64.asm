
<%
    from pwnlib.shellcraft.aarch64.linux import syscall
%>
<%page args="fd, file, buf, flag"/>
<%docstring>
Invokes the syscall fstatat64.  See 'man 2 fstatat64' for more information.

Arguments:
    fd(int): fd
    file(char): file
    buf(stat64): buf
    flag(int): flag
</%docstring>

    ${syscall('SYS_fstatat64', fd, file, buf, flag)}
