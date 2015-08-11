<% from pwnlib.shellcraft import amd64, pretty %>
<%docstring>Copies memory.

Args:
    dest: Destination address
    src: Source address
    n: Number of bytes
</%docstring>
<%page args="dest, src, n"/>
    /* memcpy(${pretty(dest)}, ${pretty(src)}, ${pretty(n)}) */
    cld
    ${amd64.setregs({'rdi': dest, 'rsi': src, 'rcx': n})}
    rep movsb
