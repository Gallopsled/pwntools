<%page args="gid = 'egid'"/>
<%docstring>
Args: [gid (imm/reg) = egid]
    Sets the real and effective group id.
</%docstring>

% if gid == 'egid':
    /*  getegid */
    push SYS_getegid
    pop rax
    int 0x80
% else:
    push ${gid}
    pop rax
% endif

    /*  setregid(rax, rax) */
    mov rbx, rax
    mov rcx, rax
    push SYS_setregid
    pop rax
    int 0x80

    /* eof */