<%
    from pwnlib.shellcraft.amd64.linux import exit as exit
    from pwnlib.shellcraft.amd64.linux import mmap
    from pwnlib.shellcraft.amd64 import setregs, pushad, popad

    from pwnlib.shellcraft import common
    from pwnlib.util.packing import unpack
%>
<%page args="address"/>
<%docstring>
Loads a statically-linked ELF into memory and transfers control.

Arguments:
    address(int): Address of the ELF as a register or integer.
</%docstring>
<%
elf_magic = unpack('\x7fELF', 32)
die       = common.label('die')
load_one  = common.label('load_one')
next_phdr = common.label('next_phdr')
"""
Elf64_Ehdr
    +0x0000 e_ident              : unsigned char [16]
    +0x0010 e_type               : Elf64_Half
    +0x0012 e_machine            : Elf64_Half
    +0x0014 e_version            : Elf64_Word
    +0x0018 e_entry              : Elf64_Addr
    +0x0020 e_phoff              : Elf64_Off
    +0x0028 e_shoff              : Elf64_Off
    +0x0030 e_flags              : Elf64_Word
    +0x0034 e_ehsize             : Elf64_Half
    +0x0036 e_phentsize          : Elf64_Half
    +0x0038 e_phnum              : Elf64_Half
    +0x003a e_shentsize          : Elf64_Half
    +0x003c e_shnum              : Elf64_Half
    +0x003e e_shstrndx           : Elf64_Half

Elf64_Phdr
    +0x0000 p_type               : Elf64_Word
    +0x0004 p_flags              : Elf64_Word
    +0x0008 p_offset             : Elf64_Off
    +0x0010 p_vaddr              : Elf64_Addr
    +0x0018 p_paddr              : Elf64_Addr
    +0x0020 p_filesz             : Elf64_Xword
    +0x0028 p_memsz              : Elf64_Xword
    +0x0030 p_align              : Elf64_Xword
"""
e_entry  = 0x0018
e_phoff  = 0x0020
e_phnum  = 0x0038
e_phentsize = 0x0036
p_type   = 0x0000
p_offset = 0x0008
p_vaddr  = 0x0010
p_filesz = 0x0020
p_memsz  = 0x0028


PT_LOAD  = 1
%>

    ${setregs({'rsi': address})}

    /* Check the ELF header */
    mov  eax, dword ptr [rsi]
    cmp  rax, ${elf_magic}
    jnz  ${die}

    /* Discover program headers */
    mov rax, rsi
    xor rbx, rbx
    mov ebx, dword ptr ${e_phoff}
    add rax, rbx
    mov rax, [rax]
    add rax, rsi /* rax = &program headers */

    mov rbx, rsi
    add rbx, ${e_phentsize}
    movzx rbx, word ptr [rbx]  /* rbx = sizeof(program header) */

    mov rcx, rsi
    add rcx, ${e_phnum}
    movzx rcx, word ptr [rcx] /* rcx = # of program headers */

1:
    /* For each section header, mmap it to the desired address */
    push rsi
    push rcx
    push rbx
    push rax
    call ${load_one}
    pop  rax
    pop  rbx
    pop  rcx
    pop  rsi
    add  rax, rbx
    loop 1b

    /* Everything is loaded and RWX.  Find the entry point and call it */
    mov rax, rsi
    add rax, ${e_entry}
    mov rax, [rax]

    /* Set up the fake stack.
    /* AT_NULL */
    xor rbx, rbx
    push rbx
    push rbx
    /* AT_RANDOM */
    push rsp
    push 25

    push rbx /* envp */
    push rbx /* argv */
    push rbx /* argc */

    /* Invoke the entry point */
    jmp rax

${load_one}:
    push rbp
    mov  rbp, rsp

    /* If it's not a PT_LOAD header, don't care */
    mov rbx, rax
    /* add rbx, ${p_type} == zero */
    cmp dword ptr [rbx], ${PT_LOAD}
    jnz ${next_phdr}

    /* Get the destination address into rdi */
    mov rdi, rax
    add rdi, ${p_vaddr}
    mov rdi, [rdi]

    /* Get the size to mmap into rbx */
    mov rbx, rax
    add rbx, ${p_memsz}
    mov rbx, [rbx]
    shr rbx, 12
    inc rbx

    /* We can't move the program break with brk(),
       so we basically have to fake it.  Allocate
       more space than we ever expect the heap to
       need, by over-allocating space by 8x */
    shl rbx, 12 + 4

    /* Map the page in */
    ${pushad()}
    ${mmap('rdi', 'rbx', 'PROT_READ|PROT_WRITE|PROT_EXEC', 'MAP_ANONYMOUS|MAP_PRIVATE|MAP_FIXED', 0, 0)}
    /* Ignore failure */
    ${popad()}

    /* Get the source address into rsi */
    mov rbx, rax
    add rbx, ${p_offset}
    mov rbx, [rbx]
    add rsi, rbx

    /* Get the number of bytes into rcx */
    mov rcx, rax
    add rcx, ${p_filesz}
    mov rcx, [rcx]

    /* Copy the data */
    cld
    rep movsb [rdi], [rsi]

${next_phdr}:
    mov rsp, rbp
    pop rbp
    ret

${die}:
    ${exit(1)}
