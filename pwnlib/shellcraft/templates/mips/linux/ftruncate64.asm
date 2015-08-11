
<%
    from pwnlib.shellcraft.mips.linux import syscall
%>
<%page args="fd, length"/>
<%docstring>
Invokes the syscall ftruncate64.  See 'man 2 ftruncate64' for more information.

Arguments:
    fd(int): fd
    length(off64_t): length
</%docstring>

    ${syscall('SYS_ftruncate64', fd, length)}
