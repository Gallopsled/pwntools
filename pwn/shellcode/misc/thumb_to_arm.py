from pwn.internal.shellcode_helper import shellcode_reqs

@shellcode_reqs(arch = ['arm', 'thumb'])
def thumb_to_arm():
    """Returns code to switch from thumb to arm mode.

    Technically this only makes sense in thumb mode, but arm mode is included,
    so you can do:

    context('arm')
    flat(thumb_to_arm() + some_other_arm_code())

    Suitable assembler directives are includes so this will work."""

    return """
        .thumb
        .align 2
        bx pc
        nop
        .arm
        """
