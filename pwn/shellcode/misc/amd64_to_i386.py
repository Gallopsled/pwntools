from pwn.internal.shellcode_helper import shellcode_reqs

@shellcode_reqs(arch = ['i386', 'amd64'], os = ['linux', 'freebsd'])
def amd64_to_i386(os = None):
    """Returns code to switch from amd64 to i386 mode.

    Technically this only makes sense in amd64 mode, but i386 mode is included,
    so you can do:

    context('i386')
    flat(amd64_to_i386() + some_other_i386_code())

    Suitable assembler directives are includes so this will work.

    NOTE: This only works if your shellcode is in the first 4 GB of the address
    space. Otherwise you will get a SEGFAULT.
    """

    if os == 'linux':
        cs = 0x23
    elif os == 'freebsd':
        cs = 0x33
    else:
        bug("OS/arch combination is not supported (%s,%s) for amd64_to_i386" % (os, arch))

    return """
        [bits 64]
        push %s
        call $+4
.helper:
        db 0xc0
        add qword [rsp], .end - .helper
        jmp far [rsp]
.end:
        [bits 32]
        """ % hex(cs)
