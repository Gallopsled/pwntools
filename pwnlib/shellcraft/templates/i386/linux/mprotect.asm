
<%
    from pwnlib.shellcraft.i386.linux import syscall
%>
<%page args="addr, length, prot"/>
<%docstring>
Invokes the syscall mprotect.  See 'man 2 mprotect' for more information.

Arguments:
    addr(void): addr
    len(size_t): len
    prot(int): prot
</%docstring>

    ${syscall('SYS_mprotect', addr, length, prot)}
