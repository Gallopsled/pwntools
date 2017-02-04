
<%
    from pwnlib.shellcraft.arm.linux import syscall
%>
<%page args="addr, length, prot"/>
<%docstring>
Invokes the syscall mprotect.  See 'man 2 mprotect' for more information.

Arguments:
    addr(void): addr
    length(size_t): length
    prot(int): prot
</%docstring>

    ${syscall('SYS_mprotect', addr, length, prot)}
