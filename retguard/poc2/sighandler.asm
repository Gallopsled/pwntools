sighandler:
        ;; This is needed for SYS_rt_sigreturn to succeed
        add esp, 4
        ;; Patch context to act like ret
        mov eax, [esp + 0x8]    ; context
        mov ebx, [eax + 0x30]   ; REG_ESP
        mov ecx, [ebx]          ; saved EIP
        mov ebp, [eax + 0x4c]
        dec ebp                 ; addr of "ret" instruction
        mov [eax + 0x4c], ecx   ; REG_EIP
        add ebx, 4              ; pop
        mov [eax + 0x30], ebx   ; REG_ESP
        ;; Signal handlers return to linux-gate.so.1, which is not in the
        ;; whitelist.  We are in a signal handler right now, so compare our
        ;; return address with the one we are checking.  Since linux-gate.so.1
        ;; is just a kernel page, and there are to ways (old and new) to return
        ;; from a signal handler, we just see if we return to the same page.
        ;; This is a liability as linux-gate.so.1 has several int 0x80's and
        ;; sysenters.
        ;; TODO: fix plz
        mov eax, [esp - 4]      ; our own return address
        mov ebx, ecx            ; the return address we are checking
        and eax, 0xfffff000
        and ebx, 0xfffff000
        cmp ebx, eax
        je .live

.patch_whitelist:
        mov eax, 0
.patch_whitelist_end:
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
