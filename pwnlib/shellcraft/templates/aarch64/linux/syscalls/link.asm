
<%
    from pwnlib.shellcraft.aarch64.linux import syscall
%>
<%page args="from_, to"/>
<%docstring>
Invokes the syscall link.  See 'man 2 link' for more information.

Arguments:
    from(char): from
    to(char): to
</%docstring>

    ${syscall('SYS_link', from_, to)}
