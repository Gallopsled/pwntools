
<%
    from pwnlib.shellcraft.aarch64.linux import syscall
%>
<%page args="pid, stat_loc, options"/>
<%docstring>
Invokes the syscall waitpid.  See 'man 2 waitpid' for more information.

Arguments:
    pid(pid_t): pid
    stat_loc(int): stat_loc
    options(int): options
</%docstring>

    ${syscall('SYS_waitpid', pid, stat_loc, options)}
