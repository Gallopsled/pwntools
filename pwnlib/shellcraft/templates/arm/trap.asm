<%docstring>A trap instruction.</%docstring>
    nop
    nop
    nop
    mov  r0, 12
    mov  r1, sp
    BKPT 0xab
    B .
