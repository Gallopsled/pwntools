
<%
    from pwnlib.shellcraft.powerpc.linux import syscall
%>
<%page args="sig, handler"/>
<%docstring>
Invokes the syscall signal.  See 'man 2 signal' for more information.

Arguments:
    sig(int): sig
    handler(sighandler_t): handler
</%docstring>

    ${syscall('SYS_signal', sig, handler)}
