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

        %define SIGHANDLER            (ebp - base + sighandler)
        %define GOT                   (ebp - base + got)
        %define NUM_ADDRS             (ebp - base + num_addrs)
        %define WHITELIST             (ebp - base + whitelist)
        %define WHITELIST_END         (ebp - base + whitelist_end)
        %define WHITELIST_LEN         ((whitelist_end - whitelist) / 4)
        %define ENTRY_POINT           (ebp - base + entry_point)
        %define ORIG_CODE             (ebp - base + orig_code)
        %define ORIG_CODE_LEN         (orig_code_end - orig_code)
        %define CLEAR_FST_ADDR        (ebp - base + bootstrapper)
        %define CLEAR_FST_NUMB        (bootstrapper.clear_till - bootstrapper)
        %define CLEAR_SND_ADDR        (ebp - base + clear)
        %define CLEAR_SND_NUMB        (clear_end - clear)
        %define RET_POINT             (ebp - base + bootstrapper.ret_point)

        %define REL_WHITELIST       (ebp - base + sighandler.rel_whitelist + 1)
        %define REL_WHITELIST_END   (ebp - base + sighandler.rel_whitelist_end + 1)
        %define REL_RET             (ebp - base + bootstrapper.rel_ret + 1)

        %define LINK_MAP  4
        %define L_ADDR    0
        %define L_NEXT    12

        ;; Get our address
        call base
base:
bootstrapper:
        pop ebp
        ;; Relocate addresses in signal handler
        lea eax, [WHITELIST]
        mov [REL_WHITELIST], eax
        lea eax, [WHITELIST_END]
        mov [REL_WHITELIST_END], eax

        ;; Patch address into return jump
        mov eax, [ENTRY_POINT]
        lea ebx, [RET_POINT]
        sub eax, ebx
        mov [REL_RET], eax

        ;; The code below was constructed by a mix of stepping through the
        ;; execution of C-programs, reading the Linux source code and header
        ;; files and reading misleading blog posts -- good luck porting.
        ;; Set up sigaction structure
                                ; handler, flags, restore, mask
        push dword 0            ; mask (snd half)
        push dword 0            ; mask (fst half)
        push dword 0            ; restore (ignored)
        push dword SA_SIGINFO   ; flags
        lea eax, [SIGHANDLER]
        push eax                ; handler
        mov ebx, SIGSEGV        ; signum
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

        ;; Translate addresses bases on where libraries are loaded
        mov eax, [GOT]
        mov eax, [eax + LINK_MAP]
        lea ebx, [WHITELIST]    ; Current address
        lea ecx, [NUM_ADDRS]
.loop:
        test eax, eax           ; link_map null?
        jz .loop_exit
        mov edx, [eax + L_ADDR] ; load addr
.loopi:
        cmp dword [ecx], 0
        jz .loopi_exit          ; no more addrs for this obj
        add [ebx], edx          ; translate
        add ebx, 4
        dec dword [ecx]
        jmp .loopi
.loopi_exit:
        add ecx, 4              ; next counter
        mov eax, [eax + L_NEXT]
        jmp .loop
.loop_exit:

        ;; Sort whitelist
        push WHITELIST_LEN
        lea eax, [WHITELIST]
        push eax
        call quicksort
        add esp, 8

.clear:
        ;; Clear code we don't need any more
        ;; Clear from after whitelist
        mov ecx, CLEAR_SND_NUMB
        mov eax, 0xf4
        lea edi, [CLEAR_SND_ADDR]
        rep stosb
        ;; Clear until .clear_till
        mov ecx, CLEAR_FST_NUMB
        mov eax, 0xf4
        lea edi, [CLEAR_FST_ADDR]
.clear_till:
        rep stosb

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

sighandler:
        #SIGHANDLER#
sighandler_end:

whitelist:
        dd #WHITELIST#
whitelist_end:

clear:

got:
        dd #GOT#
got_end:

num_addrs:
        dd #NUM_ADDRS#
num_addrs_end:

entry_point:
        dd #ENTRY_POINT#
entry_point_end:

orig_code:
        db #ORIG_CODE#
orig_code_end:

quicksort:
        #QUICKSORT#
quicksort_end:

clear_end: