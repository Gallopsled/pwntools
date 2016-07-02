
<%
    from pwnlib.shellcraft.amd64.linux import syscall
%>
<%page args="addr, length"/>
<%docstring>
Invokes the syscall munlock.  See 'man 2 munlock' for more information.

Arguments:
    addr(void): addr
    len(size_t): len
</%docstring>

    ${syscall('SYS_munlock', addr, length)}
