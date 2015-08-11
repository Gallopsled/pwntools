
<%
    from pwnlib.shellcraft.mips.linux import syscall
%>
<%page args="addr, len, prot"/>
<%docstring>
Invokes the syscall mprotect.  See 'man 2 mprotect' for more information.

Arguments:
    addr(void): addr
    len(size_t): len
    prot(int): prot
</%docstring>

    ${syscall('SYS_mprotect', addr, len, prot)}
