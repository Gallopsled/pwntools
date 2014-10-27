<%page args="uid = 'euid'"/>
<%docstring>
Args: [uid (imm/reg) = euid]
    Sets the real and effective user id.
</%docstring>

% if uid == 'euid':
    /*  geteuid */
    push SYS_geteuid
    pop rax
    int 0x80
% else:
    push ${uid}
    pop rax
% endif

    /*  setreuid(rax, rax) */
    mov rbx, rax
    mov rcx, rax
    push SYS_setreuid
    pop rax
    int 0x80
