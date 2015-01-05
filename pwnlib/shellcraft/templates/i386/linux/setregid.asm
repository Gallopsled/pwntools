<% from pwnlib.shellcraft import i386 %>
<%page args="gid = 'egid'"/>
<%docstring>
Args: [gid (imm/reg) = egid]
    Sets the real and effective group id.
</%docstring>

% if gid == 'egid':
    /*  getegid */
    ${i386.linux.syscall('SYS_getegid')}
    ${i386.mov('ebx', 'eax')}
% else:
    ${i386.mov('ebx', gid)}
% endif

    /*  setregid(eax, eax) */
    ${i386.linux.syscall('SYS_setregid', 'ebx', 'ebx')}
