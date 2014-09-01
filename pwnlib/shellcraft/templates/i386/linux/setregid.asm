<% from pwnlib.shellcraft import i386 %>
<%docstring>setregid(getegid(), getegid())</%docstring>

    ;; getegid
    push SYS_getegid
    pop eax
    int 0x80

    ;; setregid(getegid(), getegid())
    mov ebx, eax
    mov ecx, eax
    push SYS_setregid
    pop eax
    int 0x80

    ;; hello, world

