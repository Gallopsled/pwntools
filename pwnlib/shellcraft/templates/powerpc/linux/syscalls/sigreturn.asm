
<%
    from pwnlib.shellcraft.powerpc.linux import syscall
%>
<%page args="scp"/>
<%docstring>
Invokes the syscall sigreturn.  See 'man 2 sigreturn' for more information.
</%docstring>

    ${syscall('SYS_sigreturn')}
