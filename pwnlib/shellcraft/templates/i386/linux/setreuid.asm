<%page args="uid = 'euid'"/>
<%docstring>
Args: [uid (imm/reg) = euid]
    Sets the real and effective user id.
</%docstring>

% if uid == 'euid':
    /*  geteuid */
    push SYS_geteuid
    pop eax
    int 0x80
% else:
    push ${uid}
    pop eax
% endif

    /*  setreuid(eax, eax) */
    mov ebx, eax
    mov ecx, eax
    push SYS_setreuid
    pop eax
    int 0x80

    /* fin */