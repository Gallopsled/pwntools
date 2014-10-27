<%page args="gid = 'egid'"/>
<%docstring>
Args: [gid (imm/reg) = egid]
    Sets the real and effective group id.
</%docstring>

% if gid == 'egid':
    /*  getegid */
    push SYS_getegid
    pop eax
    int 0x80
% else:
    push ${gid}
    pop eax
% endif

    /*  setregid(eax, eax) */
    mov ebx, eax
    mov ecx, eax
    push SYS_setregid
    pop eax
    int 0x80

    /* eof */