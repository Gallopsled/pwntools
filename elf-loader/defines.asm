struc   Elf32_Ehdr
    .e_ident:       resb    16
    .e_type:        resw    1
    .e_machine:     resw    1
    .e_version:     resd    1
    .e_entry:       resd    1
    .e_phoff:       resd    1
    .e_shoff:       resd    1
    .e_flags:       resd    1
    .e_ehsize:      resw    1
    .e_phentsize:   resw    1
    .e_phnum:       resw    1
    .e_shentsize:   resw    1
    .e_shnum:       resw    1
    .e_shtrndx:     resw    1
endstruc

struc   Elf32_Phdr
    .p_type:        resd    1
    .p_offset:      resd    1
    .p_vaddr:       resd    1
    .p_paddr:       resd    1
    .p_filesz:      resd    1
    .p_memsz:       resd    1
    .p_flags:       resd    1
    .p_align:       resd    1
endstruc

%define PT_LOAD 1
