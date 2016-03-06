<% from pwnlib.shellcraft import mips %>
<%page args="path, dst = '$s0'"/>
<%docstring>
Args: [path, dst (imm/reg) = $s0 ]
    Opens the specified file path and sends its content to the specified file descriptor.
</%docstring>
    /* Save dst fd for later */
    ${mips.mov('$s0', dst)}

    ${mips.pushstr(path)}

    ${mips.syscall('SYS_open', '$sp', 'O_RDONLY')}

    /* Save src fd for later */
    ${mips.mov('$s1', '$v0')}

    /* Make room for struct stat */
    sw $sp, -214($sp)
    add $sp, $sp, -206

    ${mips.syscall('SYS_fstat64', '$s1', '$sp')}
    
    /* Restore stack */
    lw $sp, -8($sp)

    /* Load file size */
    lw $a3, -206 + 60($sp)

    ${mips.syscall('SYS_sendfile', '$s0', '$s1', 0, '$a3')}

