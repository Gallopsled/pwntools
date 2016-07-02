<% from pwnlib.shellcraft import amd64 %>
<%docstring>
Push all of the registers onto the stack which i386 pushad does,
in the same order.
</%docstring>
    push {r0-r12}
