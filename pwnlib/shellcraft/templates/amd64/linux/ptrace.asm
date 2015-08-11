
<%
    from pwnlib.shellcraft.amd64.linux import syscall
%>
<%page args="request, *vararg"/>
<%docstring>
Invokes the syscall ptrace.  See 'man 2 ptrace' for more information.

Arguments:
    request(ptrace_request): request
    vararg(int): vararg
</%docstring>

    ${syscall('SYS_ptrace', request, *vararg)}
