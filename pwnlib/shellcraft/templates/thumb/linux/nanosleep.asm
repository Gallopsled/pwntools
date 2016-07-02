
<%
    from pwnlib.shellcraft.thumb.linux import syscall
%>
<%page args="requested_time, remaining"/>
<%docstring>
Invokes the syscall nanosleep.  See 'man 2 nanosleep' for more information.

Arguments:
    requested_time(timespec): requested_time
    remaining(timespec): remaining
</%docstring>

    ${syscall('SYS_nanosleep', requested_time, remaining)}
