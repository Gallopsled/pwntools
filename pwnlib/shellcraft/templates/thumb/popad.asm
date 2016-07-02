<% from pwnlib.shellcraft import amd64 %>
<%docstring>
Pop all of the registers onto the stack which i386 popad does,
in the same order.
</%docstring>
    pop {r0-r12}
