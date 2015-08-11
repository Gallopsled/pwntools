
<%
    from pwnlib.shellcraft.aarch64.linux import syscall
%>
<%page args="addr, length, prot, flags, fd, offset"/>
<%docstring>
Invokes the syscall mmap.  See 'man 2 mmap' for more information.

Arguments:
    addr(void): addr
    length(size_t): length
    prot(int): prot
    flags(int): flags
    fd(int): fd
    offset(off_t): offset
</%docstring>

    ${syscall('SYS_mmap', addr, length, prot, flags, fd, offset)}
