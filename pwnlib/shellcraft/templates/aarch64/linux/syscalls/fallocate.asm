
<%
    from pwnlib.shellcraft.aarch64.linux import syscall
%>
<%page args="fd, mode, offset, length"/>
<%docstring>
Invokes the syscall fallocate.  See 'man 2 fallocate' for more information.

Arguments:
    fd(int): fd
    mode(int): mode
    offset(off_t): offset
    len(off_t): len
</%docstring>

    ${syscall('SYS_fallocate', fd, mode, offset, length)}
