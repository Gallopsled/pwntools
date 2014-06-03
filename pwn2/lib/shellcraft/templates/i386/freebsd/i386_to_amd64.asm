<%docstring>Returns code to switch from i386 to amd64 mode.</%docstring>
[bits 32]
    push 0x43
    call $+4
${common.label("helper")}:
    db 0xc0
    add dword [esp], ${common.label("end")} - ${common.lastlabel("helper")}
    jmp far [esp]
${common.lastlabel("end")}:
[bits 64]
