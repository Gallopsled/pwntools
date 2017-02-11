
<%
    from pwnlib.shellcraft.thumb.linux import syscall
%>
<%page args="fildes"/>
<%docstring>
Invokes the syscall fdatasync.  See 'man 2 fdatasync' for more information.

Arguments:
    fildes(int): fildes
</%docstring>

    ${syscall('SYS_fdatasync', fildes)}
