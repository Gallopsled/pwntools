
<%
    from pwnlib.shellcraft.amd64.linux import syscall
%>
<%page args="sig, act, oact"/>
<%docstring>
Invokes the syscall sigaction.  See 'man 2 sigaction' for more information.

Arguments:
    sig(int): sig
    act(sigaction): act
    oact(sigaction): oact
</%docstring>

    ${syscall('SYS_sigaction', sig, act, oact)}
