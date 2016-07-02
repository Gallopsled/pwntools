
<%
    from pwnlib.shellcraft.powerpc.linux import syscall
%>
<%page args="option, vararg"/>
<%docstring>
Invokes the syscall prctl.  See 'man 2 prctl' for more information.

Arguments:
    option(int): option
    vararg(int): vararg
</%docstring>

    ${syscall('SYS_prctl', option, vararg)}
