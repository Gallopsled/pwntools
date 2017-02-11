
<%
    from pwnlib.shellcraft.powerpc.linux import syscall
%>
<%page args="fd, offset, whence"/>
<%docstring>
Invokes the syscall lseek.  See 'man 2 lseek' for more information.

Arguments:
    fd(int): fd
    offset(off_t): offset
    whence(int): whence
</%docstring>

    ${syscall('SYS_lseek', fd, offset, whence)}
