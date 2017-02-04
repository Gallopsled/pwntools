
<%
    from pwnlib.shellcraft.i386.linux import syscall
%>
<%page args="resource, rlimits"/>
<%docstring>
Invokes the syscall setrlimit.  See 'man 2 setrlimit' for more information.

Arguments:
    resource(rlimit_resource_t): resource
    rlimits(rlimit): rlimits
</%docstring>

    ${syscall('SYS_setrlimit', resource, rlimits)}
