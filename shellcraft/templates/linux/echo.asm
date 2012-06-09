bits 32
        %include "linux/32.asm"
        %include "macros/pushstr.asm"

        %define str `#STR`
        xor eax, eax
        cdq                     ; EDX := 0
        %strlen cnt str
        %if cnt < 256
          mov dl, cnt
        %else
        %if cnt < 65536
          mov dx, cnt
        %else
          mov edx, cnt
        %endif
        %endif
        pushstr str
        mov ecx, esp
        %ifnum #OUT
          xor ebx, ebx
          mov bl, #OUT
        %else
          mov ebx, #OUT
        %endif
        mov al, SYS_write
        int 0x80