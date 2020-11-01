# -*- coding: utf-8 -*-
import six

class Gadget(object):
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
    move = 0

    def __init__(self, address, insns, regs, move):
        self.address = address
        self.insns   = insns
        self.regs    = regs
        self.move    = move

    __indices = ['address', 'details']

    def __repr__(self):
        return "%s(%#x, %r, %r, %#x)" % (self.__class__.__name__,
                                         self.address,
                                         self.insns,
                                         self.regs,
                                         self.move)

    def __getitem__(self, key):
        # Backward compatibility
        if isinstance(key, six.integer_types):
            key = self.__indices[key]
        return getattr(self, key)

    def __setitem__(self, key, value):
        # Backward compatibility
        if isinstance(key, six.integer_types):
            key = self.__indices[key]
        return setattr(self, key, value)
