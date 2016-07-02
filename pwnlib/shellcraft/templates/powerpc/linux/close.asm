
<%
    from pwnlib.shellcraft.powerpc.linux import syscall
%>
<%page args="fd"/>
<%docstring>
Invokes the syscall close.  See 'man 2 close' for more information.

Arguments:
    fd(int): fd
</%docstring>

    ${syscall('SYS_close', fd)}
