
<%
    from pwnlib.shellcraft.i386.linux import syscall
%>
<%page args="pid, resource, new_limit, old_limit"/>
<%docstring>
Invokes the syscall prlimit64.  See 'man 2 prlimit64' for more information.

Arguments:
    pid(pid_t): pid
    resource(rlimit_resource): resource
    new_limit(rlimit64): new_limit
    old_limit(rlimit64): old_limit
</%docstring>

    ${syscall('SYS_prlimit64', pid, resource, new_limit, old_limit)}
