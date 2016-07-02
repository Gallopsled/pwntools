<%
    from pwnlib.shellcraft.amd64.linux import syscall
%>
<%docstring>
Invokes the syscall sigreturn.  See 'man 2 sigreturn' for more information.
</%docstring>

    ${syscall('SYS_rt_sigreturn')}
