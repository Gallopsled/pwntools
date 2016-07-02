<%
    from pwnlib.shellcraft import okay
    from pwnlib.shellcraft.i386 import cgc, mov
%>
<%page args="src, dst, n=0x80"/>
<%docstring>
Forwards data from one file descriptor to another.

For more information, see:
https://github.com/CyberGrandChallenge/libcgc/blob/master/allocate.md

Arguments:
    src(int): Source file descriptor
    dst(int): Destination file descriptor
</%docstring>

    push ebp
    mov  ebp, esp
% if n <= 0x80:
    add esp, -${n}
    ${cgc.receive(src, 'esp', n, 0)}
%else:
    ${mov('eax', n)}
    sub esp, eax
    ${cgc.transmit(src, 'esp', 'eax', 0)}
%endif
    ${cgc.transmit(dst, 'esp', n, 0)}
    mov  esp, ebp
    pop  ebp
