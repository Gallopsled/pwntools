import struct

# Reference : http://lxr.free-electrons.com/source/arch/i386/include/asm/sigcontext.h?v=2.6.28#L138
_registers_32 = ["gs",   "fs",  "es",  "ds",   "edi",  "esi", "ebp", "esp", "ebx",
        "edx",  "ecx", "eax", "trapno", "err", "eip", "cs",  "eflags",
        "esp_at_signal", "ss",  "fpstate"]

# Reference : https://www.cs.vu.nl/~herbertb/papers/srop_sp14.pdf
_registers_64 = ["uc_flags", "&uc", "uc_stack.ss_sp", "uc_stack.ss_flags", "uc_stack.ss_size",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rdi", "rsi", "rbp",
        "rbx", "rdx", "rax", "rcx", "rsp", "rip", "eflags", "csgsfs", "err", "trapno",
        "oldmask", "cr2", "&fpstate", "__reserved", "sigmask"]

_reg_pos_mapping_i386 = {}
for pos, reg in enumerate(_registers_32):
    _reg_pos_mapping_i386[reg] = pos

_reg_pos_mapping_amd64 = {}
for pos, reg in enumerate(_registers_64):
    _reg_pos_mapping_amd64[reg] = pos

class SigreturnFrame(object):
    r"""
    Crafts a sigreturn frame with values that are loaded up into
    registers.

    Arguments:
        arch(str):
            The architecture. Currently ``i386`` and ``amd64`` are
            supported.

    Examples:

        >>> # Crafting a SigreturnFrame that calls mprotect on amd64
        >>> s = SigreturnFrame(arch="amd64")
        >>> frame = s.get_frame()
        >>> print repr(frame)
        '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x003\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        >>> assert len(frame) == 248
        >>> s.set_regvalue("rax", 0xa)
        >>> s.set_regvalue("rdi", 0x00601000)
        >>> s.set_regvalue("rsi", 0x1000)
        >>> s.set_regvalue("rdx", 0x7)
        >>> frame = s.get_frame()
        >>> assert len(frame) == 248
        >>> print repr(frame)
        '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10`\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x07\x00\x00\x00\x00\x00\x00\x00\n\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x003\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

        >>> # Crafting a SigreturnFrame that calls mprotect on i386
        >>> s = SigreturnFrame(arch="i386")
        >>> frame = s.get_frame()
        >>> print repr(frame)
        '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00s\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00{\x00\x00\x00\x00\x00\x00\x00'
        >>> assert len(frame) == 80
        >>> s.set_regvalue("eax", 125)
        >>> s.set_regvalue("ebx", 0x00601000)
        >>> s.set_regvalue("ecx", 0x1000)
        >>> s.set_regvalue("edx", 0x7)
        >>> frame = s.get_frame()
        >>> assert len(frame) == 80
        >>> print repr(frame)
        '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10`\x00\x07\x00\x00\x00\x00\x10\x00\x00}\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00s\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00{\x00\x00\x00\x00\x00\x00\x00'
    """

    def __init__(self, arch="i386"):
        self.arch  = arch
        self.frame = []
        self._initialize_vals()

    def _initialize_vals(self):
        if self.arch == "i386":
            self._initialize_i386()
        elif self.arch == "amd64":
            self._initialize_amd64()

    def _initialize_amd64(self):
        for i in range(len(_registers_64)):
            self.frame.append(struct.pack("<Q", 0x0))
        self.set_regvalue("csgsfs", 0x33)

    def _initialize_i386(self):
        for i in range(len(_registers_32)):
            self.frame.append(struct.pack("<I", 0x0))
        self.set_regvalue("cs", 0x73)
        self.set_regvalue("ss", 0x7b)

    def set_regvalue(self, reg, val):
        """
        Sets a specific ``reg`` to a ``val``
        """
        if self.arch == "i386":
            self._set_regvalue_i386(reg, val)
        elif self.arch == "amd64":
            self._set_regvalue_amd64(reg, val)

    def _set_regvalue_amd64(self, reg, val):
        index = _reg_pos_mapping_amd64[reg]
        value = struct.pack("<Q", val)
        self.frame[index] = value

    def _set_regvalue_i386(self, reg, val):
        index = _reg_pos_mapping_i386[reg]
        value = struct.pack("<I", val)
        if reg == "ss":
            value = struct.pack("<h", val) + "\x00\x00"
        self.frame[index] = value

    def get_frame(self):
        frame_contents = ''.join(self.frame)
        if self.arch == "i386":
            assert len(frame_contents) == len(_registers_32) * 4
        elif self.arch == "amd64":
            assert len(frame_contents) == len(_registers_64) * 8
        return frame_contents

if __name__ == '__main__':
    import doctest
    doctest.testmod()
