<% from pwnlib.shellcraft import i386 %>
<%page args="uid = 'euid'"/>
<%docstring>
Args: [uid (imm/reg) = euid]
    Sets the real and effective user id.
</%docstring>

% if uid == 'euid':
    /*  geteuid */
    ${i386.linux.syscall('SYS_geteuid')}
    ${i386.mov('ebx', 'eax')}
% else:
    ${i386.mov('ebx', uid)}
% endif

    /*  setreuid(eax, eax) */
    ${i386.syscall('SYS_setreuid', 'ebx', 'ebx')}
