bits 32
%include "linux/32.asm"

%define URANDOM_FD 0x7f
%define URANDOM_COUNT 16
%define NOISE_EXTRA_STACK 128

main:
    call no_signals
    call open_urandom
    call shudder
    jmp $

open_urandom:
    ; push '/dev/urandom\0\0\0\0'
    push 0
    push 'ndom'
    push '/ura'
    push '/dev'

    ; open("/dev/urandom", O_RDONLY | O_NONBLOCK)
    push SYS_open
    pop eax
    mov ebx, esp
    push O_RDONLY | O_NONBLOCK
    pop ecx
    int 0x80

    ; dup2(opened_fd, URANDOM_FD)
    push URANDOM_FD
    pop ecx
    mov ebx, eax
    push SYS_dup2
    pop eax
    int 0x80

    ; close(opened_fd)
    push SYS_close
    pop eax
    int 0x80

    add esp, 16
    ret

no_signals:
    ; Ignore every signal (that you can ignore)
    ; This has multiple nice effects:
    ; - It doesn't leave zombie-children
    ; - It will not die on SIGTERM
    push 127
.loop:
    push SYS_signal
    pop eax
    pop ebx
    push ebx
    push SIG_IGN
    pop ecx
    int 0x80
    dec byte [esp]
    jno .loop

    pop eax         ; remove the counter
    ret

shudder:
    push 127
.loop:
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
    push byte SYS_setsid
    pop eax
    int 0x80
    dec esi
.parent:
    call mix
    xor edi, esi
    pop eax
    js die
.continue:
    dec byte [esp]
    jno .loop

    pop eax                 ; remove counter from stack
    ret

die:
    xor ebx, ebx
    push byte SYS_exit
    pop eax
    int 0x80

mix:
    ; Cannot be called from an address which is less than 0x411 below an unmapped address
    pushad
    mov eax, [esp+36]   ; Get the first argument 
    mov ebx, [esp+32]   ; Get the return address
    lea edx, [esp+403]  ; Get some address on the stack
    mov ecx, 0x3f5
.loop:
    xor edi, dword [esp + 4*ecx + 8]
    rol edi, 13
    sub edi, eax
    rol edi, 17
    xlatb
    add eax, ecx
    xor edi, eax
    rol edi, 23
    xchg ebx, edx
    sub edi, dword [esp + 2*ecx + 8]
    ;; add more crazyness here
    loop .loop
    add esp, 32
    ret

noise:

.urandom:
    ; Read from urandom if available
    sub esp, URANDOM_COUNT + NOISE_EXTRA_STACK
    mov ecx, esp
    push URANDOM_COUNT
    pop edx
    push URANDOM_FD
    pop ebx
    push SYS_read
    pop eax
    int 0x80

.times:
    ; Call SYS_times
    xor ebx, ebx
    push byte SYS_times
    pop eax
    int 0x80
    push eax

.cpuids:
    ; Get all the cpuids and mix after every one of them
    xor eax, eax
    cpuid
    mov ebp, eax
.loop:
    mov eax, ebp
    cpuid
    call mix
    dec ebp
    jns .loop


    add esp, URANDOM_COUNT + NOISE_EXTRA_STACK + 4
    ret
