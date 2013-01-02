[bits 32]

%define BIT_COUNT 2048
%define BYTE_COUNT (BIT_COUNT / 8)
%define WORD_COUNT (BYTE_COUNT / 4)

[section .text]
global main

; computes a := a + (b << c)
; edi = destination a (as many bits as needed -- ripple just continues)
; esi = source b (2048 bits)
; ecx = uint32_t c (0 <= c <= 31)
;
; Clobbered:
; - eax = current stuff
; - ebp = carry stuff
; - ebx = shift stuff
; - edx = counter
shift_add:
    xor edx, edx
    xor ebp, ebp
shift_add.loop:
    mov eax, [esi+4*edx]
    xor ebx, ebx
    shld ebx, eax, cl
    shl eax, cl
    add eax, ebp
    adc ebx, 0
    add [edi + 4*edx], eax
    adc ebx, 0
    mov ebp, ebx
    inc edx
    cmp edx, WORD_COUNT
    jne shift_add.loop
    add [edi + 4*edx], ebp
    jb shift_add.ripple
    ret

shift_add.ripple:
    inc edx
    inc dword [edi + 4*edx]
    jb shift_add.ripple
    ret

; Computes a := b*c
; edi = destination (4096 bits)
; esi = b (2048 bits)
; ebp = c (2048 bits)
mul:
    xor eax, eax
    mov ecx, WORD_COUNT*2
    rep stosd

    sub edi, BYTE_COUNT*2

    mov ecx, WORD_COUNT*WORD_COUNT

mul.outer_loop:
    xor ebx, ebx
mul.inner_loop:
    mov eax, [esi]
    mul dword [ebp]
    add eax, ebx
    adc edx, 0
    add [edi], eax
    adc edx, 0
    mov ebx, edx
    add ebp, 4
    add edi, 4
    dec ecx

    test ecx, WORD_COUNT-1
    jne mul.inner_loop

    add [edi], ebx
    jb mul.ripple
mul.back_from_ripple:

    sub ebp, BYTE_COUNT
    sub edi, BYTE_COUNT-4
    add esi, 4

    test ecx, ecx
    jne mul.outer_loop

    sub edi, BYTE_COUNT
    sub esi, BYTE_COUNT

    ret

mul.ripple:
    xor ebx, ebx
mul.ripple2:
    inc ebx
    inc dword [edi+4*ebx]
    jb mul.ripple2
    jmp mul.back_from_ripple

div_by_2_to_BITSIZE:

main:
    mov edi, n0
    mov esi, n1
    mov ebp, n2
    call mul
    int3

[section .data]

n0:
   dd 0
   times WORD_COUNT*4 dd 0

n1:
    dd 0x1ff6eae0, 0x14e16fe6, 0x6a18e59e, 0x51bf08dc, 0xe079259a, 0x9a8ab08b, 0x2976a863, 0xade775a3, 0x99fe7793, 0xb2bc7375, 0x4c408c76, 0x76ded9c7, 0x6d5b6b39, 0x2d287343, 0x557e1d9b, 0x97f81d23, 0xff7e1cc4, 0x3e5c543b, 0xa356625a, 0xbd711fcb, 0x8725e22f, 0x81d1a230, 0x6f27f36e, 0xe4659eff, 0x14f25303, 0x1d687a4d, 0xd19e18a4, 0x98f39bbd, 0x4f46291a, 0x526d9c5f, 0xda9a49d2, 0x41596dc4, 0xf7e38718, 0xe92b715b, 0x7f995bb7, 0x07343c33, 0xcdf29a8f, 0x1e1db4d4, 0xf8fffb0b, 0xdcb3ce6f, 0xe8d85fc0, 0x48d2bb9b, 0xfcc16c12, 0xb505a90a, 0x3746dedf, 0xf3e9488a, 0x9a98416a, 0x1d326aca, 0x2dd01a46, 0x72ffa278, 0xab06ded6, 0x8c404dfc, 0x9e2277f3, 0x8162db07, 0x1f1ec59d, 0x12fd21d9, 0x17d64ba6, 0xc386f4f4, 0x7d7e2aa1, 0x45a295b0, 0xc2e1fc24, 0xf74ffaee, 0xb08fa588, 0x3845b498
    times WORD_COUNT*4 dd 0
n2:
    dd 0xd5f3306e, 0x7e9b8f44, 0x1a345116, 0xb5928537, 0x59c62033, 0x019539fb, 0xe5a357c1, 0xabe86b84, 0x70e43dae, 0xf0a6c03b, 0x98a313e9, 0x4c5bd05c, 0x784993b4, 0xb1199379, 0xfd54b0d9, 0x90217f16, 0x041a7dc6, 0x3fbfa5ab, 0xaa567ec4, 0x5285ed3e, 0xc1904505, 0x3f34cf0b, 0x24eecfe8, 0xcc48a93e, 0xe3d399d2, 0xaf3ec76e, 0x999e5be7, 0x4c5a02ef, 0x4073b733, 0xe4d7cac3, 0x37463e1f, 0x3742bdbe, 0x45285f97, 0x0c46d4c7, 0xef72962b, 0x02a30153, 0x5980705a, 0x9f2bbfe0, 0x6892538a, 0x6b15d6de, 0x4294792c, 0xede95f45, 0x5b69bfe5, 0x6370d7df, 0x9452bd71, 0x2cd941c2, 0xf4b558ac, 0x2115eaf4, 0xa69c965c, 0x8795fc0a, 0x8cf4d394, 0x18e448a3, 0xf7521ac0, 0x29400457, 0x7e1c488c, 0x1699410a, 0x43d4d6bc, 0x96611210, 0xbfe4611e, 0x555f3500, 0x732d26ba, 0x9ea4099f, 0x14e148a7, 0xe3ba7831
    times WORD_COUNT*4 dd 0

