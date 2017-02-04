
<%
    from pwnlib.shellcraft.thumb.linux import syscall
%>
<%page args="pid, pgid"/>
<%docstring>
Invokes the syscall setpgid.  See 'man 2 setpgid' for more information.

Arguments:
    pid(pid_t): pid
    pgid(pid_t): pgid
</%docstring>

    ${syscall('SYS_setpgid', pid, pgid)}
