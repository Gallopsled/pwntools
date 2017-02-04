
<%
    from pwnlib.shellcraft.i386.linux import syscall
%>
<%page args="fd, fd2"/>
<%docstring>
Invokes the syscall dup.  See 'man 2 dup' for more information.

Arguments:
    fd(int): fd
</%docstring>

    ${syscall('SYS_dup', fd)}
