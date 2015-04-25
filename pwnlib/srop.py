import struct

# Reference : http://lxr.free-electrons.com/source/arch/x86/include/asm/sigcontext.h?v=2.6.28#L138
_registers_32 = ["gs",   "fs",  "es",  "ds",   "edi",  "esi", "ebp", "esp", "ebx",
        "edx",  "ecx", "eax", "trapno", "err", "eip", "cs",  "eflags",
        "esp_at_signal", "ss",  "fpstate"]

# Reference : https://www.cs.vu.nl/~herbertb/papers/srop_sp14.pdf
_registers_64 = ["uc_flags", "&uc", "uc_stack.ss_sp", "uc_stack.ss_flags", "uc_stack.ss_size",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rdi", "rsi", "rbp",
        "rbx", "rdx", "rax", "rcx", "rsp", "rip", "eflags", "csgsfs", "err", "trapno",
        "oldmask", "cr2", "&fpstate", "__reserved", "sigmask"]

_reg_pos_mapping_x86 = {}
for pos, reg in enumerate(_registers_32):
    _reg_pos_mapping_x86[reg] = pos

_reg_pos_mapping_x64 = {}
for pos, reg in enumerate(_registers_64):
    _reg_pos_mapping_x64[reg] = pos

class SigreturnFrame(object):
    r"""
    Crafts a sigreturn frame with values that are loaded up into
    registers.

    Arguments:
        arch(str):
            The architecture. Currently ``x86`` and ``x64`` are
            supported.

    Examples:

        >>> # Crafting a SigreturnFrame that calls mprotect
        >>> s = SigreturnFrame(arch="x64")
        >>> frame.set_regvalue("rax", 0xa)
        >>> frame.set_regvalue("rdi", 0x00601000)
        >>> frame.set_regvalue("rsi", 0x1000)
        >>> frame.set_regvalue("rdx", 0x7)
        >>> frame.set_regvalue("rsp", OFFSET_INTO_PAYLOAD)
        >>> frame.set_regvalue("rip", SYSCALL)
        >>> sploit += frame.get_frame()
    """

    def __init__(self, arch="x86"):
        self.arch  = arch
        self.frame = []
        self._initialize_vals()

    def _initialize_vals(self):
        if self.arch == "x86":
            self._initialize_x86()
        elif self.arch == "x64":
            self._initialize_x64()

    def _initialize_x64(self):
        for i in range(len(_registers_64)):
            self.frame.append(struct.pack("<Q", 0x0))
        self.set_regvalue("csgsfs", 0x33)

    def _initialize_x86(self):
        for i in range(len(_registers_32)):
            self.frame.append(struct.pack("<I", 0x0))
        self.set_regvalue("cs", 0x73)
        self.set_regvalue("ss", 0x7b)

    def set_regvalue(self, reg, val):
        """
        Sets a specific ``reg`` to a ``val``
        """
        if self.arch == "x86":
            self._set_regvalue_x86(reg, val)
        elif self.arch == "x64":
            self._set_regvalue_x64(reg, val)

    def _set_regvalue_x64(self, reg, val):
        index = _reg_pos_mapping_x64[reg]
        value = struct.pack("<Q", val)
        self.frame[index] = value

    def _set_regvalue_x86(self, reg, val):
        index = _reg_pos_mapping_x86[reg]
        value = struct.pack("<I", val)
        if reg == "ss":
            value = struct.pack("<h", val) + "\x00\x00"
        self.frame[index] = value

    def get_frame(self):
        frame_contents = ''.join(self.frame)
        if self.arch == "x86":
            assert len(frame_contents) == len(_registers_32) * 4
        elif self.arch == "x64":
            assert len(frame_contents) == len(_registers_64) * 8
        return frame_contents
