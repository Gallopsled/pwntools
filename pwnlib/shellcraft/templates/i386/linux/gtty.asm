
<%
    from pwnlib.shellcraft.i386.linux import syscall
%>
<%page args="fd, params"/>
<%docstring>
Invokes the syscall gtty.  See 'man 2 gtty' for more information.

Arguments:
    fd(int): fd
    params(sgttyb): params
</%docstring>

    ${syscall('SYS_gtty', fd, params)}
