
<%
    from pwnlib.shellcraft.aarch64.linux import syscall
%>
<%page args="fromfd, from_, tofd, to, flags"/>
<%docstring>
Invokes the syscall linkat.  See 'man 2 linkat' for more information.

Arguments:
    fromfd(int): fromfd
    from(char): from
    tofd(int): tofd
    to(char): to
    flags(int): flags
</%docstring>

    ${syscall('SYS_linkat', fromfd, from_, tofd, to, flags)}
