
<%
    from pwnlib.shellcraft.i386.linux import syscall
%>
<%page args="fd, length"/>
<%docstring>
Invokes the syscall ftruncate.  See 'man 2 ftruncate' for more information.

Arguments:
    fd(int): fd
    length(off_t): length
</%docstring>

    ${syscall('SYS_ftruncate', fd, length)}
