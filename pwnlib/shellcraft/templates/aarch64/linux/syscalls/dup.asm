
<%
    from pwnlib.shellcraft.aarch64.linux import syscall
%>
<%page args="fd"/>
<%docstring>
Invokes the syscall dup.  See 'man 2 dup' for more information.

Arguments:
    fd(int): fd
</%docstring>

    ${syscall('SYS_dup', fd)}
