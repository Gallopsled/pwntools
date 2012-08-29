bits 32
%include "linux/32.asm"

%macro PRINT0 0
        push eax
        push ecx
        push byte `0`
        mov ebx, STD_OUT
        mov edx, 1
        mov ecx, esp
        mov eax, SYS_write
        int 0x80
        add esp, 4
        pop ecx
        pop eax
%endmacro
%macro PRINT1 0
        push eax
        push ecx
        push byte `1`
        mov ebx, STD_OUT
        mov edx, 1
        mov ecx, esp
        mov eax, SYS_write
        int 0x80
        add esp, 4
        pop ecx
        pop eax
%endmacro

;; int3
shudder:
        push byte 0
.loop:
        dec byte [esp]
        call noise
        push byte SYS_getpid
        pop eax
        int 0x80
        push eax
        push byte SYS_fork
        pop eax
        int 0x80
        xor esi, esi
        test eax, eax
        jnz .parent
.child:
        ;; push byte 0
        push byte SYS_getpid
        pop eax
        int 0x80
        dec esi
        jmp .roulette
.parent:
        ;; push byte 1
.roulette:
        call mix
        add edi, esi
        pop esi
        sub edi, esi
        jp .continue
.die:
        ;; test ebx, ebx
        ;; je .foo
        ;; PRINT1
        ;; jmp .bar
.foo:
        ;; PRINT0
.bar:
;;         xor ecx, ecx
;; .sleep_loop:
;;         loop .sleep_loop
        push byte SYS_exit
        pop eax
        int 0x80
.continue:
        jnz .loop
        pop eax                 ; remove counter from stack
jmp $



mix:
        pushad
        mov ecx, 0x1000
.loop:
        crc32 edi, dword [esp + ecx + 8]
        rol edi, 13
        ;; add more crazyness here
        loop .loop
        add esp, 32
        ret

noise:
        push byte SYS_times
        pop eax
        int 0x80
        call mix
        xor eax, eax
        cpuid
        mov ebp, eax
.loop:
        mov eax, ebp
        cpuid
        call mix
        dec ebp
        jns .loop
        ret