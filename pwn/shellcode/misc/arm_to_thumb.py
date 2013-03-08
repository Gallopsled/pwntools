from pwn.internal.shellcode_helper import shellcode_reqs

@shellcode_reqs(arch = ['arm', 'thumb'])
def arm_to_thumb():
    """Returns code to switch from arm to thumb mode.

    Technically this only makes sense in arm mode, but thumb mode is included,
    so you can do:

    context('thumb')
    flat(arm_to_thumb() + some_other_thumb_code())

    Suitable assembler directives are includes so this will work.
    """

    return """
        .arm
        add r3, pc, #1
        bx r3
        .thumb
        """
