<% from pwnlib.shellcraft import aarch64, pretty, common %>
<%docstring>Copies memory.

Args:
    dest: Destination address
    src: Source address
    n: Number of bytes
</%docstring>
<%page args="dest, src, n"/>
<%
memcpy_loop = common.label("memcpy_loop")
%>
    /* memcpy(${pretty(dest)}, ${pretty(src)}, ${pretty(n)}) */
    ${aarch64.setregs({'x0': dest, 'x1': src, 'x2': n})}
${memcpy_loop}:
    ldrb w3, [x1], #1
    strb w3, [x0], #1
    subs x2, x2, #1
    bge ${memcpy_loop}
