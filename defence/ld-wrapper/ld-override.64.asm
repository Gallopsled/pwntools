[bits 64]
section .text
global wrapper
global skip_real
extern consistency_check
extern lookup_function
extern thread_stack
extern rand

struc STATE
    .RAX: resq 1
    .RBX: resq 1
    .RCX: resq 1
    .RDX: resq 1
    .RBP: resq 1
    .RDI: resq 1
    .RSI: resq 1
    .R8:  resq 1
    .R9:  resq 1
    .R10: resq 1
    .R12: resq 1
    .R13: resq 1
    .R14: resq 1
    .R15: resq 1
    .RSP: resq 1
    .FUNCTION: resq 1
    .RIP: resq 1
endstruc

struc FUNCTION
    .REAL: resq 1
    .WRAPPER: resq 1
    .NAME: resq 1
endstruc

wrapper:
    ; Fill in the missing pieces to make a valid _save_state
    push rsp
    add qword [rsp], 8
    push r15
    push r14
    push r13
    push r12
    push r10
    push r9
    push r8
    push rsi
    push rdi
    push rbp
    push rdx
    push rcx
    push rbx
    push rax

    ; Call consistency_check with a pointer to the _save_state
    mov rdi, rsp
    mov qword r11, consistency_check
    call r11
    
    ; Make sure the function pointer is valid
    mov rdi, [rsp+STATE.FUNCTION]
    mov qword r11, lookup_function
    call r11

    ; Save state on  thread_stack
    ; Results in everything but the arguments themselves being popped
    mov qword r11, thread_stack
    call r11
    add qword [rax], STATE_size

    mov r11, [rax]
    xor rcx, rcx

.loop:
    pop rdx
    mov [r11-STATE_size+rcx], rdx
    add rcx, 8
    cmp rcx, STATE_size
    jl .loop
    

    ; Call the wrapper function
    mov rax, [r11-STATE_size+STATE.RAX]
    mov rcx, [r11-STATE_size+STATE.RCX]
    mov rdx, [r11-STATE_size+STATE.RDX]
    mov rdi, [r11-STATE_size+STATE.RDI]
    mov rsi, [r11-STATE_size+STATE.RSI]
    mov r8,  [r11-STATE_size+STATE.R8]
    mov r9,  [r11-STATE_size+STATE.R9]
    mov r10, [r11-STATE_size+STATE.R10]
    mov r11, [r11-STATE_size+STATE.FUNCTION]
    mov r11, [r11+FUNCTION.WRAPPER]
    call r11

    ; Call the real function
    mov qword r11, thread_stack
    call r11
    mov r11, [rax]
    mov rax, [r11-STATE_size+STATE.RAX]
    mov rcx, [r11-STATE_size+STATE.RCX]
    mov rdx, [r11-STATE_size+STATE.RDX]
    mov rdi, [r11-STATE_size+STATE.RDI]
    mov rsi, [r11-STATE_size+STATE.RSI]
    mov r8,  [r11-STATE_size+STATE.R8]
    mov r9,  [r11-STATE_size+STATE.R9]
    mov r10, [r11-STATE_size+STATE.R10]
    mov r11, [r11-STATE_size+STATE.FUNCTION]
    mov r11, [r11+FUNCTION.REAL]
    call r11

    ; Make the return value be an argument to skip_real
    mov rdi, rax

skip_real:
    push rdi
    ; Find the thread_stack
    mov qword r11, thread_stack
    call r11
    mov r11, [rax]

    ; Get the value to return when done from the stack
    pop rdx
    
    ; Restore callee-saved values
    mov rbx, [r11-STATE_size+STATE.RBX]
    mov rbp, [r11-STATE_size+STATE.RBP]
    mov r12, [r11-STATE_size+STATE.R12]
    mov r13, [r11-STATE_size+STATE.R13]
    mov r14, [r11-STATE_size+STATE.R14]
    mov r15, [r11-STATE_size+STATE.R15]
    mov rsp, [r11-STATE_size+STATE.RSP]
    mov r11, [r11-STATE_size+STATE.RIP]
    mov [rsp], r11

    ; Clean up the thread_stack
    sub qword [rax], STATE_size

    ; Push the return value to the local stack
    push rdx

    ; Get a lot of garbage and put it on the stack
    xor rcx, rcx
    mov ecx, (2*8)

.loop2:
    push rcx
    mov qword rax, rand
    call rax
    pop rcx

    shl rax, 32
    push rax
    add rsp, 4

    loop .loop2

    pop rcx
    pop rdx
    pop rsi
    pop rdi
    pop r8
    pop r9
    pop r10
    pop r11

    ; Return
    pop rax
    ret
