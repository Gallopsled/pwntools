<% from pwnlib.shellcraft import amd64 %>
<%page args="uid = 'euid'"/>
<%docstring>
Args: [uid (imm/reg) = euid]
    Sets the real and effective user id.
</%docstring>

% if uid == 'euid':
    /*  geteuid */
    ${amd64.linux.syscall('SYS_geteuid')}
    ${amd64.mov('rdi', 'rax')}
% else:
    ${amd64.mov('rdi', uid)}
% endif

    ${amd64.linux.syscall('SYS_setreuid', 'rdi', 'rdi')}
