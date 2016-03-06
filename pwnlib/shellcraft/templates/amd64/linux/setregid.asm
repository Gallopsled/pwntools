<% from pwnlib.shellcraft import amd64 %>
<%page args="gid = 'egid'"/>
<%docstring>
Args: [gid (imm/reg) = egid]
    Sets the real and effective group id.
</%docstring>

% if gid == 'egid':
    /*  getegid */
    ${amd64.linux.syscall('SYS_getegid')}
    ${amd64.mov('rdi', 'rax')}
% else:
    ${amd64.mov('rdi', gid)}
% endif

    ${amd64.linux.syscall('SYS_setregid', 'rdi', 'rdi')}
