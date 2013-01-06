bits 32
        %define SYS_sigaction  67
        %define SYS_sigreturn  119
        %define SYS_mprotect   125
        %define SYS_rt_sigreturn                173
        %define SYS_rt_sigaction                174
        %define PROT_READ      1
        %define PROT_WRITE     2
        %define PROT_EXEC      4
        %define SA_SIGINFO	   0x00000004
        %define SA_RESTART	   0x10000000
        %define SIGTRAP        5
        %define SIGILL         4
        %define SIGSEGV        11

        %define HANDLE_SIGTRAP    (ebp - base + handle_sigtrap)
        %define ENTRY_POINT       (ebp - base + entry_point)
        %define ADDRS             (ebp - base + addrs)
        %define ADDRS_END         (ebp - base + addrs_end)
        %define PATCH_ADDRS       (ebp - base + patch_addrs + 1)
        %define PATCH_ADDRS_END   (ebp - base + patch_addrs_end + 1)
        %define ORIG_CODE         (ebp - base + orig_code)
        %define PATCH_RET         (ebp - base + patch_ret + 2)
        %define ORIG_CODE_LEN     (orig_code_end - orig_code)

        ;; Get our address
        jmp bottom
top:
        pop ebp

        ;; Patch addresses in signal handler
        lea eax, [ADDRS]
        mov [PATCH_ADDRS], eax
        lea eax, [ADDRS_END]
        mov [PATCH_ADDRS_END], eax

        ;; Patch address into return jump
        lea eax, [ENTRY_POINT]
        mov [PATCH_RET], eax

        ;; The code below was constructed by a mix of stepping through the
        ;; execution of C-programs, reading the Linux source code and header
        ;; files and reading misleading blog posts -- good luck porting.
        ;; Set up sigaction structure
                                ; handler, flags, restore, mask
        push dword 0            ; mask (snd half)
        push dword 0            ; mask (fst half)
        push dword 0            ; restore (ignored)
        push dword SA_SIGINFO   ; flags
        push HANDLE_SIGTRAP
        mov ebx, SIGTRAP        ; signum
        mov ecx, esp            ; act
        xor edx, edx            ; oldact
        mov esi, 8              ; sigsetsize
        mov eax, SYS_rt_sigaction
        int 0x80
        ;; Clean up stack
        add esp, 4 * 5

        ;; Register signal handler

        ;; Mark _start as RWX
        mov ebx, [ENTRY_POINT]
        mov ecx, ebx
        add ecx, ORIG_CODE_LEN + 0xfff
        and ecx, 0xfffff000     ; ciel
        and ebx, 0xfffff000     ; floor
        sub ecx, ebx
        ;; Save for when we restore prot
        push ecx
        push ebx
        mov edx, PROT_READ | PROT_WRITE | PROT_EXEC
        mov eax, SYS_mprotect
        int 0x80

        ;; Rewrite _start
        mov edi, [ENTRY_POINT]
        lea esi, [ORIG_CODE]
        mov ecx, ORIG_CODE_LEN
        rep movsb

        ;; Restore prot on _start
        pop ebx
        pop ecx
        mov edx, PROT_READ | PROT_EXEC
        mov eax, SYS_mprotect
        int 0x80

        ;; Restore registers saved by loader
        popa

patch_ret:
        ;; Jump back to _start
        ;; The address of _start will be patched in during bootstrapping
        ;; I could not find out which registers are clobberable, so better be
        ;; safe than sorry.  This technique ensures that all registers are
        ;; restored.
        jmp [0]

bottom:
        call top

base:
handle_sigtrap:
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

patch_addrs:
        mov eax, 0
patch_addrs_end:
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
        cmp ebx, 0x3A
        jl .digit
        add ebx, 0x10
.digit:
        dec edx
        mov [edi + edx], bl
        jne .loop
        ret

addrs:
        dd #RETURN_ADDRS#
addrs_end:

entry_point:
        dd #ENTRY_POINT#

orig_code:
        db #ORIG_CODE#
orig_code_end: