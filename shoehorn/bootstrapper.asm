bits 32
        %define SYS_write      4
        %define SYS_open       5
        %define SYS_lseek      19
        %define SYS_sigaction  67
        %define SYS_readlink   85
        %define SYS_sigreturn  119
        %define SYS_mprotect   125
        %define SYS_rt_sigreturn                173
        %define SYS_rt_sigaction                174
        %define SEEK_SET       0
        %define O_WRONLY       1
        %define PROT_READ      1
        %define PROT_WRITE     2
        %define PROT_EXEC      4
        %define SA_SIGINFO     0x00000004
        %define SA_RESTART     0x10000000
        %define SIGTRAP        5
        %define SIGILL         4
        %define SIGSEGV        11

        %define ORIG_CODE             (ebp - base + orig_code)
        %define BUF                   (ebp - base + buf)
        %define BUF_LEN               (buf_end - buf)
        %define ORIG_CODE_LEN         (orig_code_end - orig_code)
        %define RET_POINT             (ebp - base + bootstrapper.ret_point)
        %define REL_RET               (ebp - base + bootstrapper.rel_ret + 1)

        ;; Get our address
        call base
base:

bootstrapper:
        pop ebp                 ; points at `base`

        ;; Patch address into return jump
        mov eax, #ORIG_ADDR#
        lea ebx, [RET_POINT]
        sub eax, ebx
        mov [REL_RET], eax

        ;; Mark original code as RWX
        mov ebx, #ORIG_ADDR#
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

        ;; Write original code back
        mov edi, #ORIG_ADDR#
        lea esi, [ORIG_CODE]
        mov ecx, ORIG_CODE_LEN
        rep movsb

        ;; Restore prot on original code
        pop ebx
        pop ecx
        mov edx, PROT_READ | PROT_EXEC
        mov eax, SYS_mprotect
        int 0x80

        call payload

        ;; Restore registers saved by loader
        popf
        popa

.rel_ret:
        ;; Jump back to _start
        ;; The address of _start will be patched in during bootstrapping
        ;; I could not find out which registers are clobberable, so better be
        ;; safe than sorry.  This technique ensures that all registers are
        ;; restored.
        jmp dword 0
.ret_point:

orig_code:
        db #ORIG_CODE#
orig_code_end:

payload: