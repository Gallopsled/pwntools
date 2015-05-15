# -*- coding: utf-8 -*-

class Gadget(dict):
    """
    Describes a ROP gadget
    """

    #: Address of the first instruction of the gadget
    address = 0

    #: List of disassembled instruction mnemonics
    #:
    #: Examples:
    #:      ['pop eax', 'ret']
    insns = []

    #: OrderedDict of register to:
    #:
    #: - Offset from the top of the frame at which it's set
    #: - Name of the register which it is set from
    #:
    #: Order is determined by the order of instructions.
    #:
    #: Examples:
    #:
    #: ret => {}
    #: pop eax; ret => {'eax': 0}
    #: pop ebx; pop eax; ret => {'ebx': 0, 'eax': 4}
    #: add esp, 0x10; pop ebx; ret => {'ebx': 16}
    #: mov eax, ebx; ret => {'eax': 'ebx'}
    regs = {}

    #: The total amount that the stack pointer is modified by
    #:
    #: Examples:
    #:      ret ==> 4
    #:      add esp, 0x10; ret ==> 0x14
    sp_move = 0


    def __getitem__(self, key):
        # Backward compatibility
        return getattr(self, key)

    def __setitem__(self, key, value):
        # Backward compatibility
        return setattr(self, key, value)
