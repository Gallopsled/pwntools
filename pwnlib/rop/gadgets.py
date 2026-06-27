class Gadget:
    """
    Describes a ROP gadget
    """

    #: Address of the first instruction of the gadget
    address: int

    #: List of disassembled instruction mnemonics
    #:
    #: Examples:
    #:      ['pop eax', 'ret']
    insns: list[str]

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
    regs: dict[str, int | str]

    #: The total amount that the stack pointer is modified by
    #:
    #: Examples:
    #:      ret ==> 4
    #:      add esp, 0x10; ret ==> 0x14
    move: int

    def __init__(self, address: int, insns: list[str], regs: dict[str, int | str], move: int):
        self.address = int(address)
        self.insns   = insns
        self.regs    = regs
        self.move    = move

    __indices = ['address', 'details']

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.address:#x}, {self.insns!r}, {self.regs!r}, {self.move:#x})"

    def __getitem__(self, key: str | int) -> object:
        # Backward compatibility
        if isinstance(key, int):
            key = self.__indices[key]
        return getattr(self, key)

    def __setitem__(self, key: str | int, value: object) -> None:
        # Backward compatibility
        if isinstance(key, int):
            key = self.__indices[key]
        return setattr(self, key, value)
