
<%
    from pwnlib.shellcraft.i386.linux import syscall
%>
<%page args="scp"/>
<%docstring>
Invokes the syscall sigreturn.  See 'man 2 sigreturn' for more information.

Arguments:
    scp(sigcontext): scp
</%docstring>

    ${syscall('SYS_sigreturn', scp)}
