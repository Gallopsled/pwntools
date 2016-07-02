<% from pwnlib.shellcraft import amd64 %>
<%docstring>
Push all of the registers onto the stack which i386 pushad does,
in the same order.
</%docstring>
    push rax
    push rcx
    push rdx
    push rbp
    push rsp
    push rbp
    push rsi
    push rdi
