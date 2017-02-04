
<%
    from pwnlib.shellcraft.powerpc.linux import syscall
%>
<%page args="from_, to"/>
<%docstring>
Invokes the syscall symlink.  See 'man 2 symlink' for more information.

Arguments:
    from(char): from
    to(char): to
</%docstring>

    ${syscall('SYS_symlink', from_, to)}
