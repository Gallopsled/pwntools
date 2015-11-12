
<%
    from pwnlib.shellcraft.amd64.linux import syscall
%>
<%page args="fdin, offin, fdout, offout, length, flags"/>
<%docstring>
Invokes the syscall splice.  See 'man 2 splice' for more information.

Arguments:
    fdin(int): fdin
    offin(off64_t): offin
    fdout(int): fdout
    offout(off64_t): offout
    len(size_t): len
    flags(unsigned): flags
</%docstring>

    ${syscall('SYS_splice', fdin, offin, fdout, offout, length, flags)}
