<% from pwnlib.shellcraft import i386 %>
<%docstring>setreuid(geteuid(), geteuid())</%docstring>

    ;; geteuid
    push SYS_geteuid
    pop eax
    int 0x80

    ;; setreuid(geteuid(), geteuid())
    mov ebx, eax
    mov ecx, eax
    push SYS_setreuid
    pop eax
    int 0x80

    ;; hello, world

