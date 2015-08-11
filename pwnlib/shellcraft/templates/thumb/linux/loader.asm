<%
    from pwnlib.shellcraft.thumb.linux import exit as exit
    from pwnlib.shellcraft.thumb.linux import mmap
    from pwnlib.shellcraft.thumb import setregs, mov, push, memcpy

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
elf_magic = unpack('\x7fELF')
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

    ${setregs({'r0': address})}

    /* Check the ELF header */
    ldr  r1,  [r0]
    ${mov('r2', elf_magic)}
    cmp  r1, r2
    bne  ${die}

    /* Discover program headers */
    add r1, r0, #${e_phoff}
    ldr r1, [r1]
    add r1, r0 /* r1 = &program headers */

    add r2, r0, #${e_phentsize}
    ldrh r2, [r2] /* r2 = program header size */

    add r3, r0, #${e_phnum}
    ldrh r3, [r3] /* r3 = number of program headers */

1:
    /* For each section header, mmap it to the desired address */
    push {r0, r1, r2, r3}
    bl   ${load_one}
    pop  {r0, r1, r2, r3}
    add  r1, r2
    subs r3, #1
    bne 1b

    /* Everything is loaded and RWX.  Find the entry point and call it */
    add r1, r0, #${e_entry}
    ldr r1, [r1]
    mov lr, r1

    /* Set up the fake stack.
       For whatever reason, ARM binaries really want AT_RANDOM
       to be available. */
    /* AT_NULL */
    eor r0, r0
    eor r1, r1
    push {r0, r1}
    /* AT_RANDOM */
    mov r0, #25
    mov r1, sp
    push {r0, r1}

    /* argc, argv, envp */
    eor r0, r0
    eor r1, r1
    eor r2, r2
    push {r0, r1, r2}

    /* Invoke the entry point */
    push {lr}
    pop  {pc}

${load_one}:
    /* r1 = &program headers */
    push {fp, lr}
    mov fp, sp

    /* If it's not a PT_LOAD header, don't care */
    add r2, r1, #${p_type}
    ldr r2, [r2]
    uxth r2, r2 /* zero-extend halfword */
    cmp r2, #${PT_LOAD}
    bne ${next_phdr}

    /* Get the destination address into r2 */
    add r2, r1, ${p_vaddr}
    ldr r2, [r2]

    /* Get the size to mmap into r3 */
    add r3, r1, #${p_memsz}
    ldr r3, [r3]
    lsr r3, #12
    add r3, r3, #1

    /* We can't move the program break with brk(),
       so we basically have to fake it.  Allocate
       more space than we ever expect the heap to
       need, by over-allocating space by 8x */
    lsl r3, #12 + 4

    /* Map the page in */
    push {r0-r12}
    lsr r2, #12
    lsl r2, #12
    ${mmap('r2', 'r3', 'PROT_READ|PROT_WRITE|PROT_EXEC', 'MAP_ANONYMOUS|MAP_PRIVATE|MAP_FIXED', 0, 0)}
    /* Ignore failure */
    pop {r0-r12}

    /* Get the source address into r4 */
    add r4, r1, #${p_offset}
    ldr r4, [r4]
    add r4, r0

    /* Get the number of bytes into r5 */
    add r5, r1, #${p_filesz}
    ldr r5, [r5]

    /* Copy the data */
    push {r0-r4}
    ${memcpy('r2','r4','r5')}
    pop  {r0-r4}

${next_phdr}:
    mov sp, fp
    pop {fp, lr}
    bx lr

${die}:
    ${exit(1)}
