<%
    from pwnlib.shellcraft.amd64.linux import syscall
%>
<%page args="status = None"/>
<%docstring>
Invokes the syscall exit.  See 'man 2 exit' for more information.

Arguments:
    status(int): status

Doctest

    >>> run_assembly_exitcode(shellcraft.exit(33))
    33

</%docstring>

    ${syscall('SYS_exit', status)}
