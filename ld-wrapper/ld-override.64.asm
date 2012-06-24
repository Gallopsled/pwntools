[bits 64]
section .text
global wrapper
global skip_real
extern consistency_check
extern lookup_function
extern thread_stack
extern rand

struc STATE
    .RBX: resq 1
    .RCX: resq 1
    .RDX: resq 1
    .RBP: resq 1
    .RDI: resq 1
    .RSI: resq 1
    .R8:  resq 1
    .R9:  resq 1
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
    push r9
    push r8
    push rsi
    push rdi
    push rbp
    push rdx
    push rcx
    push rbx

    ; Call consistency_check with a pointer to the _save_state
    mov rdi, rsp
    mov qword rax, consistency_check
    call rax
    
    ; Make sure the function pointer is valid
    mov rdi, [rsp+STATE.FUNCTION]
    mov qword rax, lookup_function
    call rax

    ; Save state on  thread_stack
    ; Results in everything but the arguments themselves being popped
    mov qword rax, thread_stack
    call rax
    add qword [rax], STATE_size

    mov rax, [rax]
    xor rcx, rcx

.loop:
    pop rdx
    mov [rax-STATE_size+rcx], rdx
    add rcx, 8
    cmp rcx, STATE_size
    jl .loop
    

    ; Call the wrapper function
    mov rcx, [rax-STATE_size+STATE.RCX]
    mov rdx, [rax-STATE_size+STATE.RDX]
    mov rdi, [rax-STATE_size+STATE.RDI]
    mov rsi, [rax-STATE_size+STATE.RSI]
    mov r8,  [rax-STATE_size+STATE.R8]
    mov r9,  [rax-STATE_size+STATE.R9]
    mov rax, [rax-STATE_size+STATE.FUNCTION]
    mov rax, [rax+FUNCTION.WRAPPER]
    call rax

    ; Call the real function
    mov qword rax, thread_stack
    call rax
    mov rax, [rax]
    mov rcx, [rax-STATE_size+STATE.RCX]
    mov rdx, [rax-STATE_size+STATE.RDX]
    mov rdi, [rax-STATE_size+STATE.RDI]
    mov rsi, [rax-STATE_size+STATE.RSI]
    mov r8,  [rax-STATE_size+STATE.R8]
    mov r9,  [rax-STATE_size+STATE.R9]
    mov rax, [rax-STATE_size+STATE.FUNCTION]
    mov rax, [rax+FUNCTION.REAL]
    call rax

    ; Make the return value be an argument to skip_real
    mov rdi, rax

skip_real:
    push rdi
    ; Find the thread_stack
    mov qword rax, thread_stack
    call rax
    mov rcx, [rax]

    ; Get the value to return when done from the stack
    pop rdx
    
    ; Restore callee-saved values
    mov rbx, [rcx-STATE_size+STATE.RBX]
    mov rbp, [rcx-STATE_size+STATE.RBP]
    mov r12, [rcx-STATE_size+STATE.R12]
    mov r13, [rcx-STATE_size+STATE.R13]
    mov r14, [rcx-STATE_size+STATE.R14]
    mov r15, [rcx-STATE_size+STATE.R15]
    mov rsp, [rcx-STATE_size+STATE.RSP]
    mov rcx, [rcx-STATE_size+STATE.RIP]
    mov [rsp], rcx

    ; Clean up the thread_stack
    sub qword [rax], STATE_size

    ; Push the return value to the local stack
    push rdx

    ; Put garbage on rcx and rdx
    mov qword rax, rand
    call rax
    mov rcx, rax
    mov qword rax, rand
    call rax
    mov rdx, rax

    ; Return
    pop rax
    ret
