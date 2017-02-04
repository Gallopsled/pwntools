
<%
    from pwnlib.shellcraft.amd64.linux import syscall
%>
<%page args="addr"/>
<%docstring>
Invokes the syscall brk.  See 'man 2 brk' for more information.

Arguments:
    addr(void): addr
</%docstring>

    ${syscall('SYS_brk', addr)}
