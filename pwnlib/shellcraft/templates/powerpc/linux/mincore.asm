
<%
    from pwnlib.shellcraft.powerpc.linux import syscall
%>
<%page args="start, length, vec"/>
<%docstring>
Invokes the syscall mincore.  See 'man 2 mincore' for more information.

Arguments:
    start(void): start
    len(size_t): len
    vec(unsigned): vec
</%docstring>

    ${syscall('SYS_mincore', start, length, vec)}
