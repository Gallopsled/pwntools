<%
    from pwnlib.shellcraft.powerpc.linux import syscall
%>
<%page args="addr=0, length=4096, prot=7, flags=34, fd=-1, offset=0"/>
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
