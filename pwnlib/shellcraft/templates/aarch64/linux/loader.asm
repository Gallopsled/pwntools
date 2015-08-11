<%
    from pwnlib.shellcraft.aarch64.linux import exit as exit
    from pwnlib.shellcraft.aarch64.linux import mmap
    from pwnlib.shellcraft.aarch64 import setregs, mov, memcpy

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

    ${setregs({'x0': address})}

    /* Check the ELF header */
    ldr  x1,  [x0]
    ${mov('x2', elf_magic)}
    cmp  w1, w2
    bne  ${die}

    /* Discover program headers */
    add x1, x0, #${e_phoff}
    ldr x1, [x1]
    add x1, x1, x0 /* x1 = &program headers */

    add x2, x0, #${e_phentsize}
    ldrh w2, [x2] /* x2 = program header size */

    add x3, x0, #${e_phnum}
    ldrh w3, [x3] /* x3 = number of program headers */

1:
    /* For each section header, mmap it to the desired address */
    stp  x0, x1, [sp, #-16]!
    stp  x2, x3, [sp, #-16]!
    bl   ${load_one}
    ldp  x2, x3, [sp], #16
    ldp  x0, x1, [sp], #16

    add  x1, x1, x2
    subs x3, x3, #1
    bne 1b

    /* Everything is loaded and RWX.  Find the entry point and call it */
    add x1, x0, #${e_entry}
    ldr x1, [x1]
    mov x8, x1

    /* Set up the fake stack.
       For whatever reason, aarch64 binaries really want AT_RANDOM
       to be available. */
    /* AT_NULL */
    eor x0, x0, x0
    eor x1, x1, x1
    stp  x0, x1, [sp, #-16]!
    /* AT_RANDOM */
    mov x2, #25
    mov x3, sp
    stp  x2, x3, [sp, #-16]!

    /* argc, argv[0], argv[1], envp */
    /* ideally these could all be empty, but unfortunately
       we have to keep the stack aligned.  it's easier to
       just push an extra argument than care... */
    stp  x0, x1, [sp, #-16]! /* argv[1] = NULL, envp = NULL */
    mov  x0, 1
    mov  x1, sp
    stp  x0, x1, [sp, #-16]! /* argc = 1, argv[0] = "" */

    br x8

${load_one}:
    /* x1 = &program headers */
    stp x29, x30, [sp, #-16]!
    mov x29, sp

    /* If it's not a PT_LOAD header, don't care */
    add x2, x1, #${p_type}
    ldr x2, [x2]
    uxth w2, w2 /* zero-extend halfword */
    cmp x2, #${PT_LOAD}
    bne ${next_phdr}

    /* Get the destination address into x2 */
    add x2, x1, ${p_vaddr}
    ldr x2, [x2]

    /* Get the size to mmap into x3 */
    add x3, x1, #${p_memsz}
    ldr x3, [x3]
    lsr w3, w3, #12
    add x3, x3, #1

    /* We can't move the program break with brk(),
       so we basically have to fake it.  Allocate
       more space than we ever expect the heap to
       need, by over-allocating space by 8x */
    lsl w3, w3, #12 + 4

    /* Map the page in */
    stp x0, x1, [sp, #-16]!
    stp x2, x3, [sp, #-16]!
    lsr w2, w2, #12
    lsl w2, w2, #12
    ${mmap('x2', 'x3', 'PROT_READ|PROT_WRITE|PROT_EXEC', 'MAP_ANONYMOUS|MAP_PRIVATE|MAP_FIXED', 0, 0)}
    /* Ignore failure */
    ldp x2, x3, [sp], #16
    ldp x0, x1, [sp], #16

    /* Get the source address into x4 */
    add x4, x1, #${p_offset}
    ldr x4, [x4]
    add x4, x4, x0

    /* Get the number of bytes into x5 */
    add x5, x1, #${p_filesz}
    ldr x5, [x5]

    /* Copy the data */
    stp x0, x1, [sp, #-16]!
    stp x2, x3, [sp, #-16]!
    stp x4, x5, [sp, #-16]!
    ${memcpy('x2','x4','x5')}
    ldp x4, x5, [sp], #16
    ldp x2, x3, [sp], #16
    ldp x0, x1, [sp], #16

${next_phdr}:
    mov sp, x29
    ldp x29, x30, [sp], #16
    ret x30

${die}:
    ${exit(1)}
