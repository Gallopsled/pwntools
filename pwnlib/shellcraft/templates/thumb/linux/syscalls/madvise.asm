
<%
    from pwnlib.shellcraft.thumb.linux import syscall
%>
<%page args="addr, length, advice"/>
<%docstring>
Invokes the syscall madvise.  See 'man 2 madvise' for more information.

Arguments:
    addr(void): addr
    len(size_t): len
    advice(int): advice
</%docstring>

    ${syscall('SYS_madvise', addr, length, advice)}
