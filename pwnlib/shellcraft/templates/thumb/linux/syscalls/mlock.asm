
<%
    from pwnlib.shellcraft.thumb.linux import syscall
%>
<%page args="addr, length"/>
<%docstring>
Invokes the syscall mlock.  See 'man 2 mlock' for more information.

Arguments:
    addr(void): addr
    len(size_t): len
</%docstring>

    ${syscall('SYS_mlock', addr, length)}
