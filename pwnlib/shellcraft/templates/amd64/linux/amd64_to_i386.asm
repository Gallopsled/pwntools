<% from pwnlib.shellcraft import common %>
<%docstring>Returns code to switch from amd64 to i386 mode.

Note that you most surely want to set up some stack (and place this code)
in low address space before (or afterwards).</%docstring>
.code64
    call $+4
    .byte 0xc0  /* inc eax */
    mov byte ptr [rsp+4], 0x23  /* This is the segment we want to go to */
    retfd
.code32
