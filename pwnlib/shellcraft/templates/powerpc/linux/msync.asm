
<%
    from pwnlib.shellcraft.powerpc.linux import syscall
%>
<%page args="addr, len, flags"/>
<%docstring>
Invokes the syscall msync.  See 'man 2 msync' for more information.

Arguments:
    addr(void): addr
    len(size_t): len
    flags(int): flags
</%docstring>

    ${syscall('SYS_msync', addr, len, flags)}
