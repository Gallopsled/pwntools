<% from pwnlib.shellcraft import amd64 %>
<%docstring>
Pop all of the registers onto the stack which i386 popad does,
in the same order.
</%docstring>
    pop rdi
    pop rsi
    pop rbp
    pop rsp
    pop rbp
    pop rdx
    pop rcx
    pop rax
