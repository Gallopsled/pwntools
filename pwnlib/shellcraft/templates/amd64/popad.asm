<% from pwnlib.shellcraft import amd64 %>
<%docstring>
Pop all of the registers onto the stack which i386 popad does,
in the same order.
</%docstring>
    pop rdi
    pop rsi
    pop rbp
    pop rbx /* add rsp, 8 */
    pop rbx
    pop rdx
    pop rcx
    pop rax
