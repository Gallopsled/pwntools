
<%
    from pwnlib.shellcraft.powerpc.linux import syscall
%>
<%page args="path, argv, envp"/>
<%docstring>
Invokes the syscall execve.  See 'man 2 execve' for more information.

Arguments:
    path(char): path
    argv(char): argv
    envp(char): envp
</%docstring>

    ${syscall('SYS_execve', path, argv, envp)}
