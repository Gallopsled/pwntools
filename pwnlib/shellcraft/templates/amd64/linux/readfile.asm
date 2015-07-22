<% from pwnlib.shellcraft import amd64 %>
<%page args="path, dst = 'rdi'"/>
<%docstring>
Args: [path, dst (imm/reg) = rdi ]
    Opens the specified file path and sends its content to the specified file descriptor.
</%docstring>
    /* Save destination */
    ${amd64.mov('r8', dst)}

    ${amd64.pushstr(path)}

    ${amd64.syscall('SYS_open', 'rsp', 'O_RDONLY')}

    /* Save file descriptor for later */
    ${amd64.mov('rbx', 'rax')}

    ${amd64.syscall('SYS_fstat', 'rax', 'rsp')}

    /* Get file size */
    add rsp, 48
    mov rdx, [rsp]

    ${amd64.syscall('SYS_sendfile', 'r8', 'rbx', 0, 'rdx')}
