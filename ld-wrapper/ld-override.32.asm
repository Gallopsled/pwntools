[bits 32]
section .text
global wrapper
global skip_real
extern consistency_check
extern lookup_function
extern thread_stack
extern rand

struc STATE
    .EBX: resw 1
    .EBP: resw 1
    .EDI: resw 1
    .ESI: resw 1
    .ESP: resw 1
    .FUNCTION: resw 1
    .EIP: resw 1
endstruc

struc FUNCTION
    .REAL: resw 1
    .WRAPPER: resw 1
    .NAME: resw 1
endstruc

wrapper:
    ; Fill in the missing pieces to make a valid _save_state
    push esp
    add dword [esp], 4
    push esi
    push edi
    push ebp
    push ebx

    ; Call consistency_check with a pointer to the _save_state
    push esp
    call consistency_check
    add esp, 4
    
    ; Make sure the function pointer is valid
    push dword [esp+STATE.FUNCTION]
    call lookup_function
    add esp, 4

    ; Save state on  thread_stack
    ; Results in everything but the arguments themselves being popped
    call thread_stack
    add dword [eax], STATE_size

    mov eax, [eax]
    xor ecx, ecx

.loop:
    pop edx
    mov [eax-STATE_size+ecx], edx
    add ecx, 4
    cmp ecx, STATE_size
    jl .loop
    

    ; Call the wrapper function
    mov edx, [eax-STATE_size+STATE.FUNCTION]
    mov edx, [edx+FUNCTION.WRAPPER]
    call edx

    ; Call the real function
    call thread_stack
    mov eax, [eax]
    mov edx, [eax-STATE_size+STATE.FUNCTION]
    mov edx, [edx+FUNCTION.REAL]
    call edx

    ; Make the return value be an argument to skip_real
    push eax
    push eax

skip_real:
    ; Find the thread_stack
    call thread_stack
    mov ecx, [eax]

    ; Get the value to return when done from the stack
    pop edx
    pop edx
    
    ; Restore callee-saved values
    mov ebx, [ecx-STATE_size+STATE.EBX]
    mov ebp, [ecx-STATE_size+STATE.EBP]
    mov edi, [ecx-STATE_size+STATE.EDI]
    mov esi, [ecx-STATE_size+STATE.ESI]
    mov esp, [ecx-STATE_size+STATE.ESP]
    mov ecx, [ecx-STATE_size+STATE.EIP]
    mov [esp], ecx

    ; Clean up the thread_stack
    sub dword [eax], STATE_size

    ; Push the return value to the local stack
    push edx

    ; Put garbage on ecx and edx
    call rand
    mov ecx, eax
    call rand
    mov edx, eax

    ; Return
    pop eax
    ret
