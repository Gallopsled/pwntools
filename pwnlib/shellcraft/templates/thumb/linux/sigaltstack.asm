
<%
    from pwnlib.shellcraft.thumb.linux import syscall
%>
<%page args="ss, oss"/>
<%docstring>
Invokes the syscall sigaltstack.  See 'man 2 sigaltstack' for more information.

Arguments:
    ss(sigaltstack): ss
    oss(sigaltstack): oss
</%docstring>

    ${syscall('SYS_sigaltstack', ss, oss)}
