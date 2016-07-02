
<%
    from pwnlib.shellcraft.thumb.linux import syscall
%>
<%page args="addr, length"/>
<%docstring>
Invokes the syscall munmap.  See 'man 2 munmap' for more information.

Arguments:
    addr(void): addr
    len(size_t): len
</%docstring>

    ${syscall('SYS_munmap', addr, length)}
