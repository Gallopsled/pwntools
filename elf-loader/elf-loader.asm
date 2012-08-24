%include "linux/32.asm"
%include "linux/64.asm"
%include "defines.asm"

%define PAGE_SIZE   4096

; !!! If you change this, then change it in print_sizes.py too !!!
%define LOADER_POS  0x100000

org LOADER_POS

; ELF-loader written in shellcode for loading 32-bit static ELF-files
; It works on both 32-bit and 64-bit linux, assuming that it is possible
; to jump to 32-bit mode from 64-bit mode by doing a far jump to 0x23:ADDR

; Algorithm: (a is 32-bit only, b is 64-bit only)
; 1a:
;       Assume that a stack is available
;       where you can push at least 6 words
; 1b:
;       Allocate such a stack (this cannot be done in 32-bit
;       mode without already having memory available)
; 2:
;       Find the address of the beginning of the code using a call.
;       Find the entire length of the payload, which can be done
;       since the position of the code is known
; 3:
;       Allocate space at LOADER_POS for moving the entire payload
; 4:
;       Move the payload to LOADER_POS
; 5a:
;       Jump to LOADER
; 5b:
;       Jump to LOADER as 32-bit code
; 6:
;       Parse the elf headers and load in the relevant parts, by first
;       unmapping it's pages and then mapping them again
; 7:
;       Put a bit of content on the stack so that libc won't fail
; 8:
;       Jump to the entry-point

; Compile with:
; nasm elf-loader.asm && (cat elf-loader; python print_sizes.py elf-loader $STATIC_ELF; cat $STATIC_ELF) > payload

[bits 64]

; Step 1a/1b
detect_mode:
    xor eax, eax
    and rax, rax        ; This is a "dec eax; and eax, eax" on 32-bit

    jne short get_info

; Step 1b
alloc_stack:
    mov rax, SYS64_mmap
    xor rdi, rdi                                    ; addr
    mov rsi, 120                                    ; length
    mov rdx, PROT_READ | PROT_WRITE                 ; prot
    mov r10, MAP_SHARED | MAP_ANONYMOUS | MAP_32BIT ; flags
    xor r8, r8                                      ; fd
    xor r9, r9                                      ; offset

    syscall
    lea esp, [rax+120]

; Step 2
get_info:
    call tramp
tramp:
    pop rsi
    sub rsi, (tramp - $$)
    mov ebp, [rsi + len - $$]

; Step 3
    push SYS_mmap
    pop rax

    push 0
    push 0
    push MAP_SHARED | MAP_ANONYMOUS | MAP_FIXED
    lea ebx, [rsp - 12]
    mov dword [rbx+0], $$
    mov [rbx+4], ebp
    mov dword [rbx+8], PROT_READ | PROT_WRITE | PROT_EXEC

    int 0x80

; Step 4
    mov edi, eax
    mov ecx, [rsi + len - $$]
    rep movsb

; Step 5a/5b
    xor rax, rax
    and rax, rax
    je switch_32

; Step 5a
    mov ebx, parse_elf
    jmp rbx

; Step 5b
switch_32:
    push 0x23
    push switch_32_fix
    jmp far [rsp]

[bits 32]
switch_32_fix:
    push ss
    pop ds

    push ss
    pop es

; Step 6
parse_elf:
    movzx   ebp, word [elf_begin + Elf32_Ehdr.e_phnum]
    mov     edx, [elf_begin + Elf32_Ehdr.e_phoff]
    add     edx, elf_begin

map_loop:
    cmp dword [edx+Elf32_Phdr.p_type], PT_LOAD
    jne map_next

    mov edi, [edx + Elf32_Phdr.p_vaddr]
    and edi, ~(PAGE_SIZE-1)

    mov esi, [edx + Elf32_Phdr.p_filesz]
    dec esi
    shr esi, 12
    inc esi

map_inner_loop:
    mov ebx, edi
    mov ecx, PAGE_SIZE
    mov eax, SYS_munmap
    int 0x80

    mov [mmap_addr], edi
    mov ebx, mmap_addr
    mov eax, SYS_mmap
    int 0x80

    add edi, PAGE_SIZE
    dec esi
    jne map_inner_loop

    mov esi, [edx + Elf32_Phdr.p_offset]
    add esi, elf_begin
    mov edi, [edx + Elf32_Phdr.p_vaddr]
    mov ecx, [edx + Elf32_Phdr.p_filesz]
    rep movsb

map_next:
    add edx, Elf32_Phdr_size
    dec ebp
    jne map_loop

map_stack:
    mov dword [mmap_addr], 0
    mov dword [mmap_len], 16*PAGE_SIZE
    mov dword [mmap_flags], MAP_SHARED | MAP_ANONYMOUS | MAP_32BIT
    mov ebx, mmap_addr
    mov eax, SYS_mmap
    int 0x80
    lea esp, [eax+16*PAGE_SIZE]

; Step 7
fix_stack:
    mov ecx, 64
fix_stack_loop:
    push 0
    loop fix_stack_loop

; Step 8
    jmp [elf_begin + Elf32_Ehdr.e_entry]

mmap_addr:      dd $$
mmap_len:       dd PAGE_SIZE
mmap_prot:      dd PROT_READ | PROT_WRITE | PROT_EXEC
mmap_flags:     dd MAP_SHARED | MAP_ANONYMOUS | MAP_FIXED
mmap_fd:        dd 0
mmap_offset:    dd 0

len:
next_page equ len + 4
elf_begin equ len + 8
