
<%
    from pwnlib.shellcraft.aarch64.linux import syscall
%>
<%page args="status"/>
<%docstring>
Invokes the syscall exit.  See 'man 2 exit' for more information.

Arguments:
    status(int): status

Example:

    >>> sc = shellcraft.exit(33)
    >>> run_assembly(sc).poll(block=1)
    33
</%docstring>

    ${syscall('SYS_exit', status)}
