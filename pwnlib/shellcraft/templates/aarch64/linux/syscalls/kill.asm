
<%
    from pwnlib.shellcraft.aarch64.linux import syscall
%>
<%page args="pid, sig"/>
<%docstring>
Invokes the syscall kill.  See 'man 2 kill' for more information.

Arguments:
    pid(pid_t): pid
    sig(int): sig
</%docstring>

    ${syscall('SYS_kill', pid, sig)}
