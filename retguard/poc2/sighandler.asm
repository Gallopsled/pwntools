        %define REG_EIP   0x4c
        %define REG_ESP   0x30
        ;; This is needed for SYS_rt_sigreturn to succeed
        add esp, 4
        ;; Patch context to act like ret
        mov eax, [esp + 0x8]    ; context
        mov ebx, [eax + REG_ESP]
        mov ecx, [ebx]          ; saved EIP
        mov ebp, [eax + REG_EIP]
        mov [eax + REG_EIP], ecx
        add ebx, 4              ; add esp, 4
        mov [eax + REG_ESP], ebx

.rel_whitelist:
        mov eax, 0
.rel_whitelist_end:
        mov edi, 0
        sub edi, eax
        shr edi, 2
        dec edi                 ; j = last addr
        xor esi, esi            ; i = first addr
.loop:
        mov ebx, edi
        sub ebx, esi
        je .check
        shr ebx, 1              ; (j - i) / 2
        add ebx, esi            ; bewteen i and j
        cmp ecx, [eax + ebx * 4]
        ja .greater
        mov edi, ebx            ; adjust j
        jmp .loop
.greater:
        mov esi, ebx
        inc esi
        jmp .loop
.check:
        cmp [eax + esi * 4], ecx
        jne .die
.live:
        mov eax, SYS_rt_sigreturn
        int 0x80

.die:
;; Stack smashing detected:  ret at 0xXXXXXXXX would have returned to 0xXXXXXXXX\n
        push `\0\0!\n`
        sub esp, 6
        mov eax, ecx
        call writeaddr
        push `o 0x`
        push `ed t`
        push `turn`
        push `e re`
        push ` hav`
        push `ould`
        push `\0\0 w`
        sub esp, 6
        mov eax, ebp
        call writeaddr
        push `t 0x`
        push `et a`
        push `d: r`
        push `ecte`
        push ` det`
        push `hing`
        push `smas`
        push `ack `
        push word `St`

        mov ecx, esp
        mov ebx, 1
        mov edx, 78
        mov eax, 4
        int 0x80
        add esp, 78
        hlt

writeaddr:   ; (addr, buf)
        lea edi, [esp + 4]
        mov edx, 8
.loop:
        mov ebx, eax
        shr eax, 4
        and ebx, 0xf
        add ebx, 0x30
        cmp ebx, 0x3a
        jl .digit
        add ebx, 0x27
.digit:
        dec edx
        mov [edi + edx], bl
        jne .loop
        ret
