
<%
    from pwnlib.shellcraft.arm.linux import syscall
%>
<%page args="pipedes"/>
<%docstring>
Invokes the syscall pipe.  See 'man 2 pipe' for more information.

Arguments:
    pipedes(int): pipedes
</%docstring>

    ${syscall('SYS_pipe', pipedes)}
