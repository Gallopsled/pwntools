
<%
    from pwnlib.shellcraft.arm.linux import syscall
%>
<%page args="fdin, fdout, length, flags"/>
<%docstring>
Invokes the syscall tee.  See 'man 2 tee' for more information.

Arguments:
    fdin(int): fdin
    fdout(int): fdout
    len(size_t): len
    flags(unsigned): flags
</%docstring>

    ${syscall('SYS_tee', fdin, fdout, length, flags)}
