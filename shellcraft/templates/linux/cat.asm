        ;; ESP must point to writable memory
        %define file `#FILE`

        xor eax, eax
        xor ecx, ecx

        ;; Push file
        push eax
        pushstr file
        mov ebx, esp

        ;; open(file, 0)
        mov al, SYS_open
        int 0x80

        %ifdef DEBUG
        test eax, eax
        jl err_open
        %endif

        mov ebp, eax

        ;; read
loop:
        mov ebx, ebp
        mov ecx, esp
        push byte 0x7f
        pop edx
        push byte SYS_read
        pop eax
        int 0x80
        test eax, eax
        jle exit
        setfd ebx, #OUT
        mov ecx, esp
        mov edx, eax
        mov al, SYS_write
        int 0x80
        jmp loop
exit:
        %ifdef DEBUG
        test eax, eax
        jl err_read
        push byte 1
        pop eax
        int 0x80
err_read:
        pushstr "read failed"
        jmp err
err_open:
        pushstr "open failed"
err
        setfd ebx, #OUT
        neg eax
        push eax
        mov ecx, esp
        push byte 15
        pop edx
        push byte SYS_write
        pop eax
        int 0x80
%endif