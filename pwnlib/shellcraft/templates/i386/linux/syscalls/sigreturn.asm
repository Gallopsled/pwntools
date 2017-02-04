
<%
    from pwnlib.shellcraft.i386.linux import syscall
%>
<%docstring>
Invokes the syscall sigreturn.  See 'man 2 sigreturn' for more information.

</%docstring>

    ${syscall('SYS_sigreturn', )}
