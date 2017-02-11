
<%
    from pwnlib.shellcraft.i386.linux import syscall
%>
<%page args="pipedes, flags"/>
<%docstring>
Invokes the syscall pipe2.  See 'man 2 pipe2' for more information.

Arguments:
    pipedes(int): pipedes
    flags(int): flags
</%docstring>

    ${syscall('SYS_pipe2', pipedes, flags)}
