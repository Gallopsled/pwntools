
<%
    from pwnlib.shellcraft.thumb.linux import syscall
%>
<%page args="fd, params"/>
<%docstring>
Invokes the syscall stty.  See 'man 2 stty' for more information.

Arguments:
    fd(int): fd
    params(sgttyb): params
</%docstring>

    ${syscall('SYS_stty', fd, params)}
