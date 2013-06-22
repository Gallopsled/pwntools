from pwn.internal.shellcode_helper import shellcode_reqs

@shellcode_reqs(arch = ['i386', 'amd64'], os = ['linux', 'freebsd'])
def i386_to_amd64(os = None):
    """Returns code to switch from i386 to amd64 mode.

    Technically this only makes sense in i386 mode, but amd64 mode is included,
    so you can do:

    context('amd64')
    flat(i386_to_amd64() + some_other_amd64_code())

    Suitable assembler directives are includes so this will work."""

    if os == 'linux':
        cs = 0x33
    elif os == 'freebsd':
        cs = 0x43
    else:
        bug("OS/arch combination is not supported (%s,%s) for i386_to_amd64" % (os, arch))

    return """
        [bits 32]
        push %s
        call $+4
.helper:
        db 0xc0
        add dword [esp], .end - .helper
        jmp far [esp]
.end:
        [bits 64]
        """ % hex(cs)
