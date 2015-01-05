#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  mayhem/datatypes/elf.py
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions are
#  met:
#
#  * Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#  * Redistributions in binary form must reproduce the above
#    copyright notice, this list of conditions and the following disclaimer
#    in the documentation and/or other materials provided with the
#    distribution.
#  * Neither the name of the project nor the names of its
#    contributors may be used to endorse or promote products derived from
#    this software without specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

import ctypes

Elf32_Addr = ctypes.c_uint32
Elf32_Half = ctypes.c_uint16
Elf32_Off = ctypes.c_uint32
Elf32_Sword = ctypes.c_int32
Elf32_Word = ctypes.c_uint32

Elf64_Addr = ctypes.c_uint64
Elf64_Half = ctypes.c_uint16
Elf64_SHalf = ctypes.c_int16
Elf64_Off = ctypes.c_uint64
Elf64_Sword = ctypes.c_int32
Elf64_Word = ctypes.c_uint32
Elf64_Xword = ctypes.c_uint64
Elf64_Sxword = ctypes.c_int64

class constants:
    EI_MAG0                 = 0
    EI_MAG1                 = 1
    EI_MAG2                 = 2
    EI_MAG3                 = 3
    EI_CLASS                = 4
    EI_DATA                 = 5
    EI_VERSION              = 6
    EI_OSABI                = 7
    EI_ABIVERSION           = 8
    EI_PAD                  = 9
    EI_NIDENT               = 16

    ELFMAG0                 = 0x7f
    ELFMAG1                 = ord('E')
    ELFMAG2                 = ord('L')
    ELFMAG3                 = ord('F')

    ELFCLASSNONE            = 0
    ELFCLASS32              = 1
    ELFCLASS64              = 2

    ELFDATANONE             = 0
    ELFDATA2LSB             = 1
    ELFDATA2MSB             = 2

    # Legal values for Elf_Phdr.p_type (segment type).
    PT_NULL                 = 0
    PT_LOAD                 = 1
    PT_DYNAMIC              = 2
    PT_INTERP               = 3
    PT_NOTE                 = 4
    PT_SHLIB                = 5
    PT_PHDR                 = 6
    PT_TLS                  = 7

    # Legal values for Elf_Ehdr.e_type (object file type).
    ET_NONE                 = 0
    ET_REL                  = 1
    ET_EXEC                 = 2
    ET_DYN                  = 3
    ET_CORE                 = 4

    # Legal values for Elf_Dyn.d_tag (dynamic entry type).
    DT_NULL                 = 0
    DT_NEEDED               = 1
    DT_PLTRELSZ             = 2
    DT_PLTGOT               = 3
    DT_HASH                 = 4
    DT_STRTAB               = 5
    DT_SYMTAB               = 6
    DT_RELA                 = 7
    DT_RELASZ               = 8
    DT_RELAENT              = 9
    DT_STRSZ                = 10
    DT_SYMENT               = 11
    DT_INIT                 = 12
    DT_FINI                 = 13
    DT_SONAME               = 14
    DT_RPATH                = 15
    DT_SYMBOLIC             = 16
    DT_REL                  = 17
    DT_RELSZ                = 18
    DT_RELENT               = 19
    DT_PLTREL               = 20
    DT_DEBUG                = 21
    DT_TEXTREL              = 22
    DT_JMPREL               = 23
    DT_ENCODING             = 32

    # Legal values for Elf_Shdr.sh_type (section type).
    SHT_NULL                = 0
    SHT_PROGBITS            = 1
    SHT_SYMTAB              = 2
    SHT_STRTAB              = 3
    SHT_RELA                = 4
    SHT_HASH                = 5
    SHT_DYNAMIC             = 6
    SHT_NOTE                = 7
    SHT_NOBITS              = 8
    SHT_REL                 = 9
    SHT_SHLIB               = 10
    SHT_DYNSYM              = 11
    SHT_NUM                 = 12

    # Legal values for ST_TYPE subfield of Elf_Sym.st_info (symbol type).
    STT_NOTYPE              = 0
    STT_OBJECT              = 1
    STT_FUNC                = 2
    STT_SECTION             = 3
    STT_FILE                = 4
    STT_COMMON              = 5
    STT_TLS                 = 6

class Elf32_Ehdr(ctypes.Structure):
    _fields_ = [("e_ident", (ctypes.c_ubyte * 16)),
                ("e_type", Elf32_Half),
                ("e_machine", Elf32_Half),
                ("e_version", Elf32_Word),
                ("e_entry", Elf32_Addr),
                ("e_phoff", Elf32_Off),
                ("e_shoff", Elf32_Off),
                ("e_flags", Elf32_Word),
                ("e_ehsize", Elf32_Half),
                ("e_phentsize", Elf32_Half),
                ("e_phnum", Elf32_Half),
                ("e_shentsize", Elf32_Half),
                ("e_shnum", Elf32_Half),
                ("e_shstrndx", Elf32_Half),]

class Elf64_Ehdr(ctypes.Structure):
    _fields_ = [("e_ident", (ctypes.c_ubyte * 16)),
                ("e_type", Elf64_Half),
                ("e_machine", Elf64_Half),
                ("e_version", Elf64_Word),
                ("e_entry", Elf64_Addr),
                ("e_phoff", Elf64_Off),
                ("e_shoff", Elf64_Off),
                ("e_flags", Elf64_Word),
                ("e_ehsize", Elf64_Half),
                ("e_phentsize", Elf64_Half),
                ("e_phnum", Elf64_Half),
                ("e_shentsize", Elf64_Half),
                ("e_shnum", Elf64_Half),
                ("e_shstrndx", Elf64_Half),]

class Elf32_Phdr(ctypes.Structure):
    _fields_ = [("p_type", Elf32_Word),
                ("p_offset", Elf32_Off),
                ("p_vaddr", Elf32_Addr),
                ("p_paddr", Elf32_Addr),
                ("p_filesz", Elf32_Word),
                ("p_memsz", Elf32_Word),
                ("p_flags", Elf32_Word),
                ("p_align", Elf32_Word),]

class Elf64_Phdr(ctypes.Structure):
    _fields_ = [("p_type", Elf64_Word),
                ("p_flags", Elf64_Word),
                ("p_offset", Elf64_Off),
                ("p_vaddr", Elf64_Addr),
                ("p_paddr", Elf64_Addr),
                ("p_filesz", Elf64_Xword),
                ("p_memsz", Elf64_Xword),
                ("p_align", Elf64_Xword),]

class Elf32_Shdr(ctypes.Structure):
    _fields_ = [("sh_name", Elf32_Word),
                ("sh_type", Elf32_Word),
                ("sh_flags", Elf32_Word),
                ("sh_addr", Elf32_Addr),
                ("sh_offset", Elf32_Off),
                ("sh_size", Elf32_Word),
                ("sh_link", Elf32_Word),
                ("sh_info", Elf32_Word),
                ("sh_addralign", Elf32_Word),
                ("sh_entsize", Elf32_Word),]

class Elf64_Shdr(ctypes.Structure):
    _fields_ = [("sh_name", Elf64_Word),
                ("sh_type", Elf64_Word),
                ("sh_flags", Elf64_Xword),
                ("sh_addr", Elf64_Addr),
                ("sh_offset", Elf64_Off),
                ("sh_size", Elf64_Xword),
                ("sh_link", Elf64_Word),
                ("sh_info", Elf64_Word),
                ("sh_addralign", Elf64_Xword),
                ("sh_entsize", Elf64_Xword),]

class _U__Elf32_Dyn(ctypes.Union):
    _fields_ = [("d_val", Elf32_Sword),
                ("d_ptr", Elf32_Addr),]

class Elf32_Dyn(ctypes.Structure):
    _anonymous_ = ("d_un",)
    _fields_ = [("d_tag", Elf32_Sword),
                ("d_un", _U__Elf32_Dyn),]

class _U__Elf64_Dyn(ctypes.Union):
    _fields_ = [("d_val", Elf64_Xword),
                ("d_ptr", Elf64_Addr),]

class Elf64_Dyn(ctypes.Structure):
    _anonymous_ = ("d_un",)
    _fields_ = [("d_tag", Elf64_Sxword),
                ("d_un", _U__Elf64_Dyn),]

class Elf32_Sym(ctypes.Structure):
    _fields_ = [("st_name", Elf32_Word),
                ("st_value", Elf32_Addr),
                ("st_size", Elf32_Word),
                ("st_info", ctypes.c_ubyte),
                ("st_other", ctypes.c_ubyte),
                ("st_shndx", Elf32_Half),]

class Elf64_Sym(ctypes.Structure):
    _fields_ = [("st_name", Elf64_Word),
                ("st_info", ctypes.c_ubyte),
                ("st_other", ctypes.c_ubyte),
                ("st_shndx", Elf64_Half),
                ("st_value", Elf64_Addr),
                ("st_size", Elf64_Xword),]

class Elf32_Link_Map(ctypes.Structure):
    _fields_ = [("l_addr", Elf32_Addr),
                ("l_name", Elf32_Addr),
                ("l_ld", Elf32_Addr),
                ("l_next", Elf32_Addr),
                ("l_prev", Elf32_Addr),]

class Elf64_Link_Map(ctypes.Structure):
    _fields_ = [("l_addr", Elf64_Addr),
                ("l_name", Elf64_Addr),
                ("l_ld",   Elf64_Addr),
                ("l_next", Elf64_Addr),
                ("l_prev", Elf64_Addr),]


#
# Additions below here by Zach Riggle for pwntool
#
# See the routine elf_machine_runtime_setup for the relevant architecture
# for the layout of the GOT.
#
# https://chromium.googlesource.com/chromiumos/third_party/glibc/+/master/sysdeps/x86/dl-machine.h
# https://chromium.googlesource.com/chromiumos/third_party/glibc/+/master/sysdeps/x86_64/dl-machine.h
# https://fossies.org/dox/glibc-2.20/aarch64_2dl-machine_8h_source.html#l00074
# https://fossies.org/dox/glibc-2.20/powerpc32_2dl-machine_8c_source.html#l00203
#
# For now, these are defined for x86 and x64
#
char = ctypes.c_char
byte = ctypes.c_byte

class Elf_eident(ctypes.Structure):
    _fields_ = [('EI_MAG',char*4),
                ('EI_CLASS',byte),
                ('EI_DATA',byte),
                ('EI_VERSION',byte),
                ('EI_OSABI',byte),
                ('EI_ABIVERSION',byte),
                ('EI_PAD', byte*(16-9))]

class Elf_i386_GOT(ctypes.Structure):
    _fields_ = [("jmp", Elf32_Addr),
                ("linkmap", Elf32_Addr),
                ("dl_runtime_resolve", Elf32_Addr)]
class Elf_x86_64_GOT(ctypes.Structure):
    _fields_ = [("jmp", Elf64_Addr),
                ("linkmap", Elf64_Addr),
                ("dl_runtime_resolve", Elf64_Addr)]

class Elf_HashTable(ctypes.Structure):
    _fields_ = [('nbucket', Elf32_Word),
                ('nchain', Elf32_Word),]
              # ('bucket', nbucket * Elf32_Word),
              # ('chain',  nchain * Elf32_Word)]

# Docs: http://dyncall.org/svn/dyncall/tags/r0.4/dyncall/dynload/dynload_syms_elf.c
class GNU_HASH(ctypes.Structure):
    _fields_ = [('nbuckets',  Elf32_Word),
                ('symndx',    Elf32_Word),
                ('maskwords', Elf32_Word),
                ('shift2',    Elf32_Word)]

class Elf32_r_debug(ctypes.Structure):
    _fields_ = [('r_version', Elf32_Word),
                ('r_map', Elf32_Addr)]

class Elf64_r_debug(ctypes.Structure):
    _fields_ = [('r_version', Elf32_Word),
                ('r_map', Elf64_Addr)]

constants.DT_GNU_HASH = 0x6ffffef5
constants.STN_UNDEF   = 0
