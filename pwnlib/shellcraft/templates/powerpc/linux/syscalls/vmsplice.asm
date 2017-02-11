
<%
    from pwnlib.shellcraft.powerpc.linux import syscall
%>
<%page args="fdout, iov, count, flags"/>
<%docstring>
Invokes the syscall vmsplice.  See 'man 2 vmsplice' for more information.

Arguments:
    fdout(int): fdout
    iov(iovec): iov
    count(size_t): count
    flags(unsigned): flags
</%docstring>

    ${syscall('SYS_vmsplice', fdout, iov, count, flags)}
