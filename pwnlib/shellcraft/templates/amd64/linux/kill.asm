<% from pwnlib.shellcraft import amd64 %>
<%page args="pid, signal = 'SIGKILL'"/>
<%docstring>kill(pid, sig) -> str

Invokes the syscall kill.

See 'man 2 kill' for more information.

Arguments:
    pid(pid_t): pid
    sig(int): sig
Returns:
    int
</%docstring>

    ${amd64.linux.syscall('SYS_kill', pid, signal)}
