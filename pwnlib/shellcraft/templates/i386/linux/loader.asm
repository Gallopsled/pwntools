<%
    import pwnlib.shellcraft as sc
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
elf_magic = unpack(b'\x7fELF')
die       = common.label('die')
load_one  = common.label('load_one')
next_phdr = common.label('next_phdr')
"""
Elf32_Ehdr
    +0x0000 e_ident              : unsigned char [16]
    +0x0010 e_type               : Elf32_Half
    +0x0012 e_machine            : Elf32_Half
    +0x0014 e_version            : Elf32_Word
    +0x0018 e_entry              : Elf32_Addr
    +0x001c e_phoff              : Elf32_Off
    +0x0020 e_shoff              : Elf32_Off
    +0x0024 e_flags              : Elf32_Word
    +0x0028 e_ehsize             : Elf32_Half
    +0x002a e_phentsize          : Elf32_Half
    +0x002c e_phnum              : Elf32_Half
    +0x002e e_shentsize          : Elf32_Half
    +0x0030 e_shnum              : Elf32_Half
    +0x0032 e_shstrndx           : Elf32_Half

Elf32_Phdr
    +0x0000 p_type               : Elf32_Word
    +0x0004 p_offset             : Elf32_Off
    +0x0008 p_vaddr              : Elf32_Addr
    +0x000c p_paddr              : Elf32_Addr
    +0x0010 p_filesz             : Elf32_Word
    +0x0014 p_memsz              : Elf32_Word
    +0x0018 p_flags              : Elf32_Word
    +0x001c p_align              : Elf32_Word
"""
e_entry  = 0x0018
e_phoff  = 0x001c
e_phnum  = 0x002c
e_phentsize = 0x002a
p_type   = 0x0000
p_offset = 0x0004
p_vaddr  = 0x0008
p_filesz = 0x0010
p_memsz  = 0x0014


PT_LOAD  = 1
%>

    ${sc.setregs({'esi': address})}

    /* Check the ELF header */
    mov  eax, dword ptr [esi]
    cmp  eax, ${elf_magic}
    jnz  ${die}

    /* Discover program headers */
    mov eax, esi
    add eax, dword ptr ${e_phoff}
    mov eax, [eax]
    add eax, esi /* eax = &program headers */

    mov ebx, esi
    add ebx, ${e_phentsize}
    movzx ebx, word ptr [ebx]  /* ebx = sizeof(program header) */

    mov ecx, esi
    add ecx, ${e_phnum}
    movzx ecx, word ptr [ecx] /* ecx = # of program headers */

1:
    /* For each section header, mmap it to the desired address */
    push esi
    push ecx
    push ebx
    push eax
    call ${load_one}
    pop  eax
    pop  ebx
    pop  ecx
    pop  esi
    add  eax, ebx
    loop 1b

    /* Everything is loaded and RWX.  Find the entry point and call it */
    mov eax, esi
    add eax, ${e_entry}
    mov eax, [eax]

    /* Set up the fake stack.
    /* AT_NULL */
    xor ebx, ebx
    push ebx
    push ebx
    /* AT_RANDOM */
    push esp
    push 25

    push ebx /* envp */
    push ebx /* argv */
    push ebx /* argc */

    /* Invoke the entry point */
    jmp eax

${load_one}:
    push ebp
    mov  ebp, esp

    /* If it's not a PT_LOAD header, don't care */
    mov ebx, eax
    /* add ebx, ${p_type} == zero */
    cmp dword ptr [ebx], ${PT_LOAD}
    jnz ${next_phdr}

    /* Get the destination address into edi */
    mov edi, eax
    add edi, ${p_vaddr}
    mov edi, [edi]

    /* Get the size to mmap into ebx */
    mov ebx, eax
    add ebx, ${p_memsz}
    mov ebx, [ebx]
    shr ebx, 12
    inc ebx

    /* We can't move the program break with brk(),
       so we basically have to fake it.  Allocate
       more space than we ever expect the heap to
       need, by over-allocating space by 8x */
    shl ebx, 12 + 4

    /* Map the page in */
    pushad
    ${sc.mmap('edi', 'ebx', 'PROT_READ|PROT_WRITE|PROT_EXEC', 'MAP_ANONYMOUS|MAP_PRIVATE|MAP_FIXED', 0, 0)}
    /* Ignore failure */
    popad

    /* Get the source address into esi */
    mov ebx, eax
    add ebx, ${p_offset}
    mov ebx, [ebx]
    add esi, ebx

    /* Get the number of bytes into ecx */
    mov ecx, eax
    add ecx, ${p_filesz}
    mov ecx, [ecx]

    /* Copy the data */
    cld
    rep movsb

${next_phdr}:
    mov esp, ebp
    pop ebp
    ret

${die}:
    ${sc.exit(1)}
