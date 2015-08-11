
<%
    from pwnlib.shellcraft.amd64.linux import syscall
%>
<%page args="addr, len, advice"/>
<%docstring>
Invokes the syscall madvise.  See 'man 2 madvise' for more information.

Arguments:
    addr(void): addr
    len(size_t): len
    advice(int): advice
</%docstring>

    ${syscall('SYS_madvise', addr, len, advice)}
