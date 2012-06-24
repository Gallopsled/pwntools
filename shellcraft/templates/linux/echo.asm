        %define str `#STR`
        xor eax, eax

        %strlen cnt str
        %if cnt < 256
          cdq                   ; EDX := 0
          mov dl, cnt
        %else
        %if cnt < 65536
          cdq                   ; EDX := 0
          mov dx, cnt
        %else
          mov edx, cnt
        %endif
        %endif

        pushstr str
        setfd ebx, #OUT
        mov ecx, esp
        mov al, SYS_write
        int 0x80