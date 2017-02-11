
<%
    from pwnlib.shellcraft.mips.linux import syscall
%>
<%page args="name"/>
<%docstring>
Invokes the syscall acct.  See 'man 2 acct' for more information.

Arguments:
    name(char): name
</%docstring>

    ${syscall('SYS_acct', name)}
