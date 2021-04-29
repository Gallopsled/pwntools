<% from pwnlib.shellcraft import common %>
<%docstring>Returns code to switch from i386 to amd64 mode.</%docstring>
.code32
    push 0x33 /*  This is the segment we want to go to */
    /* "db 0xff; sub al,0x24" is "jmp far [esp]" by chance */
    call $+4
    sub al, 0x24
.code64
