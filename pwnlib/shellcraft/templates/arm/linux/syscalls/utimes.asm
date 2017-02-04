
<%
    from pwnlib.shellcraft.arm.linux import syscall
%>
<%page args="file, tvp"/>
<%docstring>
Invokes the syscall utimes.  See 'man 2 utimes' for more information.

Arguments:
    file(char): file
    tvp(timeval): tvp
</%docstring>

    ${syscall('SYS_utimes', file, tvp)}
