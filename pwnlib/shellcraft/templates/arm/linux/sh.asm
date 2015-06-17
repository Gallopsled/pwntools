<%docstring>Execute /bin/sh</%docstring>

    adr r0, bin_sh
    mov r2, #0
    mov r1, r2
    svc SYS_execve
    bin_sh: .asciz "/bin/sh"
