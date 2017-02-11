
<%
    from pwnlib.shellcraft.amd64.linux import syscall
%>
<%page args="sample_buffer, size, offset, scale"/>
<%docstring>
Invokes the syscall profil.  See 'man 2 profil' for more information.

Arguments:
    sample_buffer(unsigned): sample_buffer
    size(size_t): size
    offset(size_t): offset
    scale(unsigned): scale
</%docstring>

    ${syscall('SYS_profil', sample_buffer, size, offset, scale)}
