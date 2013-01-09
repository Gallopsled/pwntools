[bits 32]

%include "linux/32.asm"

section .text
global pwn_wrapper
extern pwn_thread_stack
extern pwn_pre_handler
extern pwn_post_handler
extern pwn_lookup_function

struc STACK
    .pushedi:           resd 1
    .pushesi:           resd 1
    .pushebp:           resd 1
    .pushesp:           resd 1
    .pushebx:           resd 1
    .pushedx:           resd 1
    .pushecx:           resd 1
    .pusheax:           resd 1
    .pushfd:            resd 1
    .function_number:   resd 1
    .function_cache:    resd 1
    .eip:               resd 1
endstruc


pwn_wrapper:
    pushfd
    pushad

    call pwn_lookup_function

    call pwn_pre_handler
    test eax, eax
    jnz .customvalue

    call pwn_thread_stack
    mov ecx, [esp + STACK.function_number]
    mov edx, [esp + STACK.eip]
    xchg [eax], esp
    push ecx
    push edx
    xchg [eax], esp

    mov dword [esp+STACK.eip], .afterreal
    popad
    popfd
    pop dword [esp-4] ; add esp, 4 without changing flags
    ret

.afterreal:
    push eax
    push eax
    push eax
    pushfd
    pushad

    call pwn_thread_stack
    xchg [eax], esp
    pop edx
    pop ecx
    xchg [eax], esp
    mov [esp + STACK.eip], edx
    mov [esp + STACK.function_number], ecx

    call pwn_post_handler
    test eax, eax
    jnz .customvalue

.exit:
    popad
    popfd
    pop dword [esp-4] ; add esp, 4 without changing flags
    pop dword [esp-4] ; add esp, 4 without changing flags
    ret

.customvalue:
    ; Small values are assumed to be error codes
    movzx ecx, al
    cmp ecx, eax
    je .abort

    ; Large values are assumed to be a pointer to
    ; the value that you want to return
    mov eax, [eax]
    mov [esp + STACK.pusheax], eax
    jmp .exit

.abort:
    mov ebx, eax
    mov eax, SYS_exit
    int 0x80
