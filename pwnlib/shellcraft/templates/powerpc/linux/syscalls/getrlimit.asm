
<%
    from pwnlib.shellcraft.powerpc.linux import syscall
%>
<%page args="resource, rlimits"/>
<%docstring>
Invokes the syscall getrlimit.  See 'man 2 getrlimit' for more information.

Arguments:
    resource(rlimit_resource_t): resource
    rlimits(rlimit): rlimits
</%docstring>

    ${syscall('SYS_getrlimit', resource, rlimits)}
