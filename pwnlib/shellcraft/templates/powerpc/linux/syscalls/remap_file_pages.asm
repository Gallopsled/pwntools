
<%
    from pwnlib.shellcraft.powerpc.linux import syscall
%>
<%page args="start, size, prot, pgoff, flags"/>
<%docstring>
Invokes the syscall remap_file_pages.  See 'man 2 remap_file_pages' for more information.

Arguments:
    start(void): start
    size(size_t): size
    prot(int): prot
    pgoff(size_t): pgoff
    flags(int): flags
</%docstring>

    ${syscall('SYS_remap_file_pages', start, size, prot, pgoff, flags)}
