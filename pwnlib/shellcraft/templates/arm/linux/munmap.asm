
<%
    from pwnlib.shellcraft.arm.linux import syscall
%>
<%page args="addr, length"/>
<%docstring>
Invokes the syscall munmap.  See 'man 2 munmap' for more information.

Arguments:
    addr(void): addr
    length(size_t): length
</%docstring>

    ${syscall('SYS_munmap', addr, length)}
