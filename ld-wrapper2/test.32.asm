[bits 32]

extern pwn_wrapper
global rand
global srand

section .text

rand:
#    int3
    push function_cache
    push 0
    jmp pwn_wrapper

srand:
#    int3
    push function_cache2
    push 1
    jmp pwn_wrapper

section .bss
    function_cache: resd 1
    function_cache2: resd 1
