<%
    from pwnlib.shellcraft.i386.cgc import syscall
%>
<%page args="buf, count, rnd_bytes"/>
<%docstring>
Invokes the syscall random.

For more information, see:
https://github.com/CyberGrandChallenge/libcgc/blob/master/random.md

Arguments:
    buf(int): buf
    count(int): count
    rnd_bytes(int): rnd_bytes
</%docstring>

    ${syscall('SYS_random', buf, count, rnd_bytes)}
