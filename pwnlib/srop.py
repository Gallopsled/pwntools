from .util.packing import pack
from .context import context
from .log import getLogger

log = getLogger(__name__)

# Reference : http://lxr.free-electrons.com/source/arch/x86/include/asm/sigcontext.h?v=2.6.28#L138
_registers_i386 = ["gs",   "fs",  "es",  "ds",   "edi",  "esi", "ebp", "esp", "ebx",
        "edx",  "ecx", "eax", "trapno", "err", "eip", "cs",  "eflags",
        "esp_at_signal", "ss",  "fpstate"]

# Reference : https://www.cs.vu.nl/~herbertb/papers/srop_sp14.pdf
_registers_amd64 = ["uc_flags", "&uc", "uc_stack.ss_sp", "uc_stack.ss_flags", "uc_stack.ss_size",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rdi", "rsi", "rbp",
        "rbx", "rdx", "rax", "rcx", "rsp", "rip", "eflags", "csgsfs", "err", "trapno",
        "oldmask", "cr2", "&fpstate", "__reserved", "sigmask"]

def get_registers(**kwargs):
    global _registers_i386, _registers_amd64
    registers = {"i386": _registers_i386, "amd64": _registers_amd64}
    with context.local(**kwargs):
        arch = context.arch
        registers = {"i386": _registers_i386, "amd64": _registers_amd64}
        return registers[arch]

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
        >>> context.arch = "amd64"
        >>> s = SigreturnFrame(arch="amd64")
        >>> frame = s.get_frame()
        >>> unpack_many(frame)
        [0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 51L, 0L, 0L, 0L, 0L, 0L, 0L, 0L]
        >>> assert len(frame) == 248
        >>> s.set_regvalue("rax", 0xa)
        >>> s.set_regvalue("rdi", 0x00601000)
        >>> s.set_regvalue("rsi", 0x1000)
        >>> s.set_regvalue("rdx", 0x7)
        >>> frame = s.get_frame()
        >>> assert len(frame) == 248
        >>> unpack_many(frame)
        [0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 6295552L, 4096L, 0L, 0L, 7L, 10L, 0L, 0L, 0L, 0L, 51L, 0L, 0L, 0L, 0L, 0L, 0L, 0L]
        >>> context.clear()

        >>> # Crafting a SigreturnFrame that calls mprotect on i386
        >>> context.arch = "i386"
        >>> s = SigreturnFrame(arch="i386")
        >>> frame = s.get_frame()
        >>> unpack_many(frame)
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 115, 0, 0, 123, 0]
        >>> assert len(frame) == 80
        >>> s.set_regvalue("eax", 125)
        >>> s.set_regvalue("ebx", 0x00601000)
        >>> s.set_regvalue("ecx", 0x1000)
        >>> s.set_regvalue("edx", 0x7)
        >>> frame = s.get_frame()
        >>> assert len(frame) == 80
        >>> unpack_many(frame)
        [0, 0, 0, 0, 0, 0, 0, 0, 6295552, 7, 4096, 125, 0, 0, 0, 115, 0, 0, 123, 0]
    """

    def __init__(self, **kwargs):
        self.frame = []
        self._registers = get_registers(**kwargs)
        self._initialize_vals()

    def _initialize_vals(self, **kwargs):
        values_to_set = { "i386" : [("cs", 0x73), ("ss", 0x7b)],
                          "amd64": [("csgsfs", 0x33)],
                        }
        for i in xrange(len(self._registers)):
            self.frame.append(pack(0x0))

        with context.local(**kwargs):
            for register, value in values_to_set[context.arch]:
                self.set_regvalue(register, value)

    def set_regvalue(self, reg, val):
        """
        Sets a specific ``reg`` to a ``val``
        """
        index = self._registers.index(reg)
        value = pack(val)
        self.frame[index] = value

    def get_spindex(self, **kwargs):
        with context.local(**kwargs):
            stackptr = {"i386": "esp", "amd64": "rsp"}
            return self._registers.index(stackptr[context.arch])

    def get_frame(self, **kwargs):
        """
        Returns the SROP frame
        """
        size = {"i386": 4, "amd64": 8}
        frame_contents = ''.join(self.frame)
        with context.local(**kwargs):
            assert len(frame_contents) == len(self._registers) * size[context.arch]
        return frame_contents
