<% from pwnlib.shellcraft import i386, pretty %>
<%docstring>Copies memory.

Args:
    dest: Destination address
    src: Source address
    n: Number of bytes
</%docstring>
<%page args="dest, src, n"/>

    /* memcpy(${pretty(dest)}, ${pretty(src)}, ${pretty(n)}) */
    cld
    ${i386.setregs({'edi': dest, 'esi': src, 'ecx': n})}
    rep movsb

