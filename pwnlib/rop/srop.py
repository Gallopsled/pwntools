# -*- coding: utf-8 -*-
r"""
Sigreturn ROP (SROP)

Sigreturn is a syscall used to restore the entire register context
from memory pointed at by ESP.

We can leverage this during ROP to gain control of registers for which
there are not convenient gadgets.  The main caveat is that *all* registers
are set, including ESP and EIP (or their equivalents).  This means that
in order to continue after using a sigreturn frame, the stack pointer
must be set accordingly.

i386 Example:

    Let's just print a message out using SROP.

    >>> message = "Hello, World"

    First, we'll create our example binary.
    It just reads some data onto the stack, and invokes
    the ``sigreturn`` syscall.
    We also make an ``int 0x80`` gadget available, followed
    immediately by ``exit(0)``.

    >>> context.clear(arch='i386')
    >>> assembly =  'read:'      + shellcraft.read(constants.STDIN_FILENO, 'esp', 1024)
    >>> assembly += 'sigreturn:' + shellcraft.sigreturn('esp')
    >>> assembly += 'int3:'      + shellcraft.trap()
    >>> assembly += 'syscall: '  + shellcraft.syscall()
    >>> assembly += 'exit: '     + 'xor ebx, ebx; mov eax, 1; int 0x80;'
    >>> assembly += 'message: '  + ('.asciz "%s"' % message)
    >>> binary = ELF.from_assembly(assembly)

    Let's construct our frame to have it invoke a ``write``
    syscall, and dump the message to stdout.

    >>> frame = SigreturnFrame(kernel='amd64')
    >>> frame.eax = constants.SYS_write
    >>> frame.ebx = constants.STDOUT_FILENO
    >>> frame.ecx = binary.symbols['message']
    >>> frame.edx = len(message)
    >>> frame.esp = 0xdeadbeef
    >>> frame.eip = binary.symbols['syscall']

    Let's start the process, send the data, and check the message.

    >>> p = process(binary.path)
    >>> p.send(str(frame))
    >>> p.recvall() == message
    True
    >>> p.wait_for_close()
    >>> p.poll() == 0
    True

"""
from collections import namedtuple

from ..abi import ABI
from ..context import context, LocalContext
from ..log import getLogger
from ..util.packing import flat
from ..util.packing import pack
from ..util.packing import unpack_many

log = getLogger(__name__)

sropregs = namedtuple('sropregs', ['context', 'offsets'])

registers = {
# Reference : http://lxr.free-electrons.com/source/arch/x86/include/asm/sigcontext.h?v=2.6.28#L138
    'i386': sropregs(["gs",   "fs",  "es",  "ds",   "edi",  "esi", "ebp", "esp", "ebx",
        "edx",  "ecx", "eax", "trapno", "err", "eip", "cs",  "eflags",
        "esp_at_signal", "ss",  "fpstate"], {}),

# Reference : https://www.cs.vu.nl/~herbertb/papers/srop_sp14.pdf
    'amd64': sropregs(["uc_flags", "&uc", "uc_stack.ss_sp", "uc_stack.ss_flags", "uc_stack.ss_size",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rdi", "rsi", "rbp",
        "rbx", "rdx", "rax", "rcx", "rsp", "rip", "eflags", "csgsfs", "err", "trapno",
        "oldmask", "cr2", "&fpstate", "__reserved", "sigmask"], {}),

# Reference : lxr.free-electrons.com/source/arch/arm/kernel/signal.c#L133
    'arm' : sropregs(["uc_flags", "uc_link", "uc_stack.ss_sp", "uc_stack.ss_flags", "uc_stack.ss_size",
		"trap_no", "error_code", "oldmask", "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
		 "r8", "r9", "r10", "fp", "ip", "sp", "lr", "pc", "cpsr", "fault_address", "uc_sigmask",
         "__unused", "uc_regspace"], {'base'  : 232,
                                      'CRUNCH': (0x5065cf03, 0xa8),
                                      'IWMMXT': (0x12ef842a, 0x98),
                                      'VFPU'  : (0x56465001, 0x120)}),
}

defaults = {
    "i386" : {"cs": 0x73, "ss": 0x7b},
    "i386_on_amd64": {"cs": 0x23, "ss": 0x2b},
    "amd64": {"csgsfs": 0x33},
    "arm": {"trap_no": 0x6, "cpsr": 0x40000010}
}

instruction_pointers = {
    'i386': 'eip',
    'amd64': 'rip',
    'arm': 'pc'
}

stack_pointers = {
    'i386': 'esp',
    'amd64': 'rsp',
    'arm': 'sp'
}

# # XXX Need to add support for Capstone in order to extract ARM and MIPS
# XXX as the SVC code may vary.
syscall_instructions = {
    'amd64': ['int 0x80', 'syscall', 'sysenter'],
    'i386': ['int 0x80', 'syscall', 'sysenter'],
    'arm': ['svc 0'],
    'aarch64': ['svc 0'],
    'thumb': ['svc 0'],
    'mips': ['syscall']
}

class SigreturnFrame(dict):
    r"""
    Crafts a sigreturn frame with values that are loaded up into
    registers.

    Arguments:
        arch(str):
            The architecture. Currently ``i386`` and ``amd64`` are
            supported.

    Examples:

        Crafting a SigreturnFrame that calls mprotect on amd64

        >>> context.clear(arch='amd64')
        >>> s = SigreturnFrame()
        >>> unpack_many(str(s))
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 51, 0, 0, 0, 0, 0, 0, 0]
        >>> assert len(s) == 248
        >>> s.rax = 0xa
        >>> s.rdi = 0x00601000
        >>> s.rsi = 0x1000
        >>> s.rdx = 0x7
        >>> assert len(str(s)) == 248
        >>> unpack_many(str(s))
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6295552, 4096, 0, 0, 7, 10, 0, 0, 0, 0, 51, 0, 0, 0, 0, 0, 0, 0]

        Crafting a SigreturnFrame that calls mprotect on i386

        >>> context.clear(arch='i386')
        >>> s = SigreturnFrame(kernel='i386')
        >>> unpack_many(str(s))
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 115, 0, 0, 123, 0]
        >>> assert len(s) == 80
        >>> s.eax = 125
        >>> s.ebx = 0x00601000
        >>> s.ecx = 0x1000
        >>> s.edx = 0x7
        >>> assert len(str(s)) == 80
        >>> unpack_many(str(s))
        [0, 0, 0, 0, 0, 0, 0, 0, 6295552, 7, 4096, 125, 0, 0, 0, 115, 0, 0, 123, 0]
    """

    arch = None
    frame = None
    size  = 0

    @LocalContext
    def __init__(self):
        if context.kernel is None and context.arch == 'i386':
            log.error("kernel architecture must be specified")

        self.arch = context.arch
        self.update({r:0 for r in self.registers})
        self.size = len(str(self))
        self.update(defaults[self.arch])

        if context.arch == 'i386' and context.kernel == 'amd64':
            self.update(defaults['i386_on_amd64'])

    def __setitem__(self, item, value):
        if item not in self.registers:
            log.error("Unknown register %r (not in %r)" % (item, self.registers))
        if self.arch == "arm" and item == "sp" and (value & 0x7):
            log.error("ARM SP should be 8-bit aligned")
        super(SigreturnFrame, self).__setitem__(item, value)

    def __setattr__(self, attr, value):
        if attr in SigreturnFrame.__dict__:
            super(SigreturnFrame, self).__setattr__(attr, value)
        else:
            self.set_regvalue(attr, value)

    def __getattr__(self, attr):
        return self[attr]

    def __str__(self):
        with context.local(arch=self.arch):
            return flat(*[self[r] for r in self.registers])

    def __len__(self):
        return self.size

    @property
    def registers(self):
        return registers[self.arch].context

    @property
    def register_offsets(self):
        return registers[self.arch].offsets

    @property
    def arguments(self):
        # Skip the register used to hold the syscall number
        return ABI.syscall(arch=self.arch).register_arguments[1:]

    @property
    def sp(self):
        return self[stack_pointers[self.arch]]

    @sp.setter
    def sp(self, v):
        self[stack_pointers[self.arch]] = v

    @property
    def pc(self):
        return self[instruction_pointers[self.arch]]

    @pc.setter
    def pc(self, v):
        self[instruction_pointers[self.arch]] = v

    @property
    def syscall(self):
        return self[self.syscall_register]

    @syscall.setter
    def syscall(self, v):
        self[self.syscall_register] = v

    @property
    def syscall_register(self):
        return ABI.syscall(arch=self.arch).syscall_register

    def fix_offsets(self, frcontents, namedoffsets):

        # If there is no offset information for the architecture
        # or if coprocessors are not specified, just return the
        # frame contents.
        offset_info = self.register_offsets
        if not offset_info:
            return frcontents
        if not namedoffsets:
            return frcontents

        def _fixup(frcontents, offsetvals, base):
            frcontents += "A" * (base - len(frcontents))
            for magicva, size in offsetvals:
                frcontents += flat([magicva, size])
                if len(frcontents) < size:
                    frcontents += "A" * (size - len(frcontents))
            return frcontents

        # Get the base offset where we start adding in co-processor
        # information.
        base = offset_info['base']
        offsetvals = []
        for key in namedoffsets:
            key = key.upper()
            try:
                offsetvals.append((offset_info[key]))
            except KeyError, e:
                log.error("Named offset '%s' not supported" % key)

        offsetvals.sort(key=lambda x: x[1])
        return _fixup(frcontents, offsetvals, base)

    def set_regvalue(self, reg, val):
        """
        Sets a specific ``reg`` to a ``val``
        """
        self[reg] = val

    def get_spindex(self):
        return self.registers.index(stack_pointers[self.arch])

    def get_frame(self, namedoffsets=None):
        """
        Returns the SROP frame. Use this function for the following
        architectures if additional registers need to be specified
        based on offsets.

        For ARM architectures use this function in case coprocessors
        need to be specified. Valid values for ARM coprocessors are
        `vfpu`, `iwmmxt` and `crunch`.
        eg:-
            s.get_frame("vfpu")
        """
        frcontents = str(self)
        frcontents = self.fix_offsets(frcontents, namedoffsets)
        return frcontents
