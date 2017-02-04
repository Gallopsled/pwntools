
<%
    from pwnlib.shellcraft.powerpc.linux import syscall
%>
<%page args="inc"/>
<%docstring>
Invokes the syscall nice.  See 'man 2 nice' for more information.

Arguments:
    inc(int): inc
</%docstring>

    ${syscall('SYS_nice', inc)}
