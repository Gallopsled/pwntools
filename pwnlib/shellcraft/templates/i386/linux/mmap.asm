<%
    from pwnlib.shellcraft.i386.linux import syscall
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

    ${syscall('SYS_mmap2', addr, length, prot, flags, fd, offset)}
