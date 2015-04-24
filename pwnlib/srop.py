import struct

registers_32 = ["gs",   "fs",  "es",  "ds",   "edi",  "esi", "ebp", "esp", "ebx",
        "edx",  "ecx", "eax", "JUNK", "JUNK", "eip", "cs",  "eflags",
        "JUNK", "ss",  "floa"]

registers_64 = ["uc_flags", "&uc", "uc_stack.ss_sp", "uc_stack.ss_flags", "uc_stack.ss_size",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rdi", "rsi", "rbp",
        "rbx", "rdx", "rax", "rcx", "rsp", "rip", "eflags", "csgsfs", "err", "trapno",
        "oldmask", "cr2", "&fpstate", "__reserved", "sigmask"]

reg_pos_mapping_x86 = {}
for pos, reg in enumerate(registers_32):
    reg_pos_mapping_x86[reg] = pos

reg_pos_mapping_x64 = {}
for pos, reg in enumerate(registers_64):
    reg_pos_mapping_x64[reg] = pos

class SigreturnFrame(object):
    def __init__(self, arch="x86"):
        self.arch  = arch
        self.frame = []
        self.initialize_vals()

    def initialize_vals(self):
        if self.arch == "x86":
            self._initialize_x86()
        elif self.arch == "x64":
            self._initialize_x64()

    def _initialize_x64(self):
        for i in range(len(registers_64)):
            self.frame.append(struct.pack("<Q", 0x0))
        self.set_regvalue("csgsfs", 0x33)
        self.set_regvalue("&fpstate", 0x0)
        self.set_regvalue("__reserved", 0x0)

    def _initialize_x86(self):
        for i in range(len(registers_32)):
            self.frame.append(struct.pack("<I", 0x0))
        self.set_regvalue("cs", 0x73)
        self.set_regvalue("ss", 0x7b)

    def set_regvalue(self, reg, val):
        if self.arch == "x86":
            self._set_regvalue_x86(reg, val)
        elif self.arch == "x64":
            self._set_regvalue_x64(reg, val)

    def _set_regvalue_x64(self, reg, val):
        index = reg_pos_mapping_x64[reg]
        value = struct.pack("<Q", val)
        self.frame[index] = value

    def _set_regvalue_x86(self, reg, val):
        index = reg_pos_mapping_x86[reg]
        value = struct.pack("<I", val)
        if reg == "ss":
            value = struct.pack("<h", val) + "\x00\x00"
        self.frame[index] = value

    def get_frame(self):
        frame_contents = ''.join(self.frame)
        if self.arch == "x86":
            assert len(frame_contents) == len(registers_32) * 4
        elif self.arch == "x64":
            assert len(frame_contents) == len(registers_64) * 8
        return frame_contents
