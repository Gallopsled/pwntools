from .util.packing import pack
from .context import context
from .log import getLogger

log = getLogger(__name__)

registers = {
# Reference : http://lxr.free-electrons.com/source/arch/x86/include/asm/sigcontext.h?v=2.6.28#L138
    'i386': ["gs",   "fs",  "es",  "ds",   "edi",  "esi", "ebp", "esp", "ebx",
        "edx",  "ecx", "eax", "trapno", "err", "eip", "cs",  "eflags",
        "esp_at_signal", "ss",  "fpstate"],

# Reference : https://www.cs.vu.nl/~herbertb/papers/srop_sp14.pdf
    'amd64': ["uc_flags", "&uc", "uc_stack.ss_sp", "uc_stack.ss_flags", "uc_stack.ss_size",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rdi", "rsi", "rbp",
        "rbx", "rdx", "rax", "rcx", "rsp", "rip", "eflags", "csgsfs", "err", "trapno",
        "oldmask", "cr2", "&fpstate", "__reserved", "sigmask"]
}

defaults = {
    "i386" : {"cs": 0x73, "ss": 0x7b},
    "amd64": {"csgsfs": 0x33}
}

stack_pointers = {
    'i386': 'esp',
    'amd64': 'rsp'
}

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

    def __init__(self, **kw):
        with context.local(**kw):
            self.arch  = context.arch
            self.frame = {r:0 for r in registers[self.arch]}
            self.frame.update(defaults[self.arch])

    def set_regvalue(self, reg, val, **kwargs):
        """
        Sets a specific ``reg`` to a ``val``
        """
        self.frame[reg] = val

    def get_spindex(self, **kwargs):
        return registers[self.arch].index(stack_pointers[self.arch])

    def get_frame(self, **kwargs):
        """
        Returns the SROP frame
        """
        return pack_many(**[self.frame[r] for r in registers[self.arch]])
