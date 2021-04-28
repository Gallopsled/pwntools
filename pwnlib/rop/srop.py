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

    >>> message = "Hello, World\\n"

    First, we'll create our example binary.
    It just reads some data onto the stack, and invokes
    the ``sigreturn`` syscall.
    We also make an ``int 0x80`` gadget available, followed
    immediately by ``exit(0)``.

    >>> context.clear(arch='i386')
    >>> assembly =  'setup: sub esp, 1024\n'
    >>> assembly += 'read:'      + shellcraft.read(constants.STDIN_FILENO, 'esp', 1024)
    >>> assembly += 'sigreturn:' + shellcraft.sigreturn()
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
    >>> p.send(bytes(frame))
    >>> p.recvline()
    b'Hello, World\n'
    >>> p.poll(block=True)
    0

amd64 Example:

    >>> context.clear()
    >>> context.arch = "amd64"
    >>> assembly =  'setup: sub rsp, 1024\n'
    >>> assembly += 'read:'      + shellcraft.read(constants.STDIN_FILENO, 'rsp', 1024)
    >>> assembly += 'sigreturn:' + shellcraft.sigreturn()
    >>> assembly += 'int3:'      + shellcraft.trap()
    >>> assembly += 'syscall: '  + shellcraft.syscall()
    >>> assembly += 'exit: '     + 'xor rdi, rdi; mov rax, 60; syscall;'
    >>> assembly += 'message: '  + ('.asciz "%s"' % message)
    >>> binary = ELF.from_assembly(assembly)
    >>> frame = SigreturnFrame()
    >>> frame.rax = constants.SYS_write
    >>> frame.rdi = constants.STDOUT_FILENO
    >>> frame.rsi = binary.symbols['message']
    >>> frame.rdx = len(message)
    >>> frame.rsp = 0xdeadbeef
    >>> frame.rip = binary.symbols['syscall']
    >>> p = process(binary.path)
    >>> p.send(bytes(frame))
    >>> p.recvline()
    b'Hello, World\n'
    >>> p.poll(block=True)
    0

arm Example:

    >>> context.clear()
    >>> context.arch = "arm"
    >>> assembly =  'setup: sub sp, sp, 1024\n'
    >>> assembly += 'read:'      + shellcraft.read(constants.STDIN_FILENO, 'sp', 1024)
    >>> assembly += 'sigreturn:' + shellcraft.sigreturn()
    >>> assembly += 'int3:'      + shellcraft.trap()
    >>> assembly += 'syscall: '  + shellcraft.syscall()
    >>> assembly += 'exit: '     + 'eor r0, r0; mov r7, 0x1; swi #0;'
    >>> assembly += 'message: '  + ('.asciz "%s"' % message)
    >>> binary = ELF.from_assembly(assembly)
    >>> frame = SigreturnFrame()
    >>> frame.r7 = constants.SYS_write
    >>> frame.r0 = constants.STDOUT_FILENO
    >>> frame.r1 = binary.symbols['message']
    >>> frame.r2 = len(message)
    >>> frame.sp = 0xdead0000
    >>> frame.pc = binary.symbols['syscall']
    >>> p = process(binary.path)
    >>> p.send(bytes(frame))
    >>> p.recvline()
    b'Hello, World\n'
    >>> p.wait_for_close()
    >>> p.poll(block=True)
    0

Mips Example:

    >>> context.clear()
    >>> context.arch = "mips"
    >>> context.endian = "big"
    >>> assembly =  'setup: sub $sp, $sp, 1024\n'
    >>> assembly += 'read:'      + shellcraft.read(constants.STDIN_FILENO, '$sp', 1024)
    >>> assembly += 'sigreturn:' + shellcraft.sigreturn()
    >>> assembly += 'syscall: '  + shellcraft.syscall()
    >>> assembly += 'exit: '     + shellcraft.exit(0)
    >>> assembly += 'message: '  + ('.asciz "%s"' % message)
    >>> binary = ELF.from_assembly(assembly)
    >>> frame = SigreturnFrame()
    >>> frame.v0 = constants.SYS_write
    >>> frame.a0 = constants.STDOUT_FILENO
    >>> frame.a1 = binary.symbols['message']
    >>> frame.a2 = len(message)
    >>> frame.sp = 0xdead0000
    >>> frame.pc = binary.symbols['syscall']
    >>> p = process(binary.path)
    >>> p.send(bytes(frame))
    >>> p.recvline()
    b'Hello, World\n'
    >>> p.poll(block=True)
    0

Mipsel Example:

    >>> context.clear()
    >>> context.arch = "mips"
    >>> context.endian = "little"
    >>> assembly =  'setup: sub $sp, $sp, 1024\n'
    >>> assembly += 'read:'      + shellcraft.read(constants.STDIN_FILENO, '$sp', 1024)
    >>> assembly += 'sigreturn:' + shellcraft.sigreturn()
    >>> assembly += 'syscall: '  + shellcraft.syscall()
    >>> assembly += 'exit: '     + shellcraft.exit(0)
    >>> assembly += 'message: '  + ('.asciz "%s"' % message)
    >>> binary = ELF.from_assembly(assembly)
    >>> frame = SigreturnFrame()
    >>> frame.v0 = constants.SYS_write
    >>> frame.a0 = constants.STDOUT_FILENO
    >>> frame.a1 = binary.symbols['message']
    >>> frame.a2 = len(message)
    >>> frame.sp = 0xdead0000
    >>> frame.pc = binary.symbols['syscall']
    >>> p = process(binary.path)
    >>> p.send(bytes(frame))
    >>> p.recvline()
    b'Hello, World\n'
    >>> p.poll(block=True)
    0

"""
from __future__ import absolute_import
from __future__ import division

from collections import namedtuple

from pwnlib.abi import ABI
from pwnlib.context import LocalContext
from pwnlib.context import context
from pwnlib.log import getLogger
from pwnlib.util.packing import flat
from pwnlib.util.packing import pack
from pwnlib.util.packing import unpack_many

log = getLogger(__name__)

registers = {
# Reference : http://lxr.free-electrons.com/source/arch/x86/include/asm/sigcontext.h?v=2.6.28#L138
        'i386' : {0: 'gs', 4: 'fs', 8: 'es', 12: 'ds', 16: 'edi', 20: 'esi', 24: 'ebp', 28: 'esp',
                  32: 'ebx', 36: 'edx', 40: 'ecx', 44: 'eax', 48: 'trapno', 52: 'err', 56: 'eip',
                  60: 'cs', 64: 'eflags', 68: 'esp_at_signal', 72: 'ss', 76: 'fpstate'},
# Reference : https://www.cs.vu.nl/~herbertb/papers/srop_sp14.pdf
        'amd64': {0: 'uc_flags', 8: '&uc', 16: 'uc_stack.ss_sp', 24: 'uc_stack.ss_flags',
                  32: 'uc_stack.ss_size', 40: 'r8', 48: 'r9', 56: 'r10', 64: 'r11', 72: 'r12',
                  80: 'r13', 88: 'r14', 96: 'r15', 104: 'rdi', 112: 'rsi', 120: 'rbp', 128: 'rbx',
                  136: 'rdx', 144: 'rax', 152: 'rcx', 160: 'rsp', 168: 'rip', 176: 'eflags',
                  184: 'csgsfs', 192: 'err', 200: 'trapno', 208: 'oldmask', 216: 'cr2',
                  224: '&fpstate', 232: '__reserved', 240: 'sigmask'},
# Reference : http://lxr.free-electrons.com/source/arch/arm/include/uapi/asm/sigcontext.h#L15
        'arm' : {0: 'uc_flags', 4: 'uc_link', 8: 'uc_stack.ss_sp', 12: 'uc_stack.ss_flags',
                 16: 'uc_stack.ss_size', 20: 'trap_no', 24: 'error_code', 28: 'oldmask', 32: 'r0',
                 36: 'r1', 40: 'r2', 44: 'r3', 48: 'r4', 52: 'r5', 56: 'r6', 60: 'r7', 64: 'r8',
                 68: 'r9', 72: 'r10', 76: 'fp', 80: 'ip', 84: 'sp', 88: 'lr', 92: 'pc', 96: 'cpsr',
                 100: 'fault_address', 104: 'uc_sigmask', 108: '__unused', 112: 'uc_regspace',
                 232: 'VFPU-magic', 236: 'VFPU-size'},
# Reference : http://lxr.free-electrons.com/source/arch/mips/include/uapi/asm/sigcontext.h#L15
        'mips': {0: 'sf_ass0', 4: 'sf_ass1', 8: 'sf_ass2', 12: 'sf_ass3', 16: 'sf_ass4', 20: 'sf_pad0',
                 24: 'sf_pad1', 28: 'sc_regmask', 32: 'sc_status', 36: 'pc', 44: 'padding', 52: 'at', 60: 'v0',
                 68: 'v1', 76: 'a0', 84: 'a1', 92: 'a2', 100: 'a3', 108: 't0', 116: 't1', 124: 't2',
                 132: 't3', 140: 't4', 148: 't5', 156: 't6', 164: 't7', 172: 's0', 180: 's1', 188: 's2',
                 196: 's3', 204: 's4', 212: 's5', 220: 's6', 228: 's7', 236: 't8', 244: 't9', 252: 'k0',
                 260: 'k1', 268: 'gp', 276: 'sp', 284: 's8', 292: 'ra'},
        'mipsel': {0: 'sf_ass0', 4: 'sf_ass1', 8: 'sf_ass2', 12: 'sf_ass3', 16: 'sf_ass4', 20: 'sc_regmask',
                   24: 'sc_status', 32: 'pc', 40: 'padding', 48: 'at', 56: 'v0', 64: 'v1', 72: 'a0',
                   80: 'a1', 88: 'a2', 96: 'a3', 104: 't0', 112: 't1', 120: 't2', 128: 't3', 136: 't4',
                   144: 't5', 152: 't6', 160: 't7', 168: 's0', 176: 's1', 184: 's2', 192: 's3', 200: 's4',
                   208: 's5', 216: 's6', 224: 's7', 232: 't8', 240: 't9', 248: 'k0', 256: 'k1', 264: 'gp',
                   272: 'sp', 280: 's8', 288: 'ra'},
        'aarch64': {312: 'x0', 320: 'x1', 328: 'x2', 336: 'x3',
                    344: 'x4',  352: 'x5', 360: 'x6', 368: 'x7',
                    376: 'x8', 384: 'x9', 392: 'x10', 400: 'x11',
                    408: 'x12', 416: 'x13', 424: 'x14', 432: 'x15',
                    440: 'x16', 448: 'x17', 456: 'x18', 464: 'x19',
                    472: 'x20', 480: 'x21', 488: 'x22', 496: 'x23',
                    504: 'x24', 512: 'x25', 520: 'x26', 528: 'x27',
                    536: 'x28', 544: 'x29', 552: 'x30', 560: 'sp',
                    568: 'pc', 592: 'magic'}
}

defaults = {
    "i386" : {"cs": 0x73, "ss": 0x7b},
    "i386_on_amd64": {"cs": 0x23, "ss": 0x2b},
    "amd64": {"csgsfs": 0x33},
    "arm": {"trap_no": 0x6, "cpsr": 0x40000010, "VFPU-magic": 0x56465001, "VFPU-size": 0x120},
    "mips": {},
    "aarch64": {"magic": 0x0000021046508001},
}

instruction_pointers = {
    'i386': 'eip',
    'amd64': 'rip',
    'arm': 'pc',
    'mips': 'pc',
    'aarch64': 'pc',
}

stack_pointers = {
    'i386': 'esp',
    'amd64': 'rsp',
    'arm': 'sp',
    'mips': 'sp',
    'aarch64': 'sp',
}

# # XXX Need to add support for Capstone in order to extract ARM and MIPS
# XXX as the SVC code may vary.
syscall_instructions = {
    'amd64': ['syscall'],
    'i386': ['int 0x80'],
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
        >>> unpack_many(bytes(s))
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 51, 0, 0, 0, 0, 0, 0, 0]
        >>> assert len(s) == 248
        >>> s.rax = 0xa
        >>> s.rdi = 0x00601000
        >>> s.rsi = 0x1000
        >>> s.rdx = 0x7
        >>> assert len(bytes(s)) == 248
        >>> unpack_many(bytes(s))
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6295552, 4096, 0, 0, 7, 10, 0, 0, 0, 0, 51, 0, 0, 0, 0, 0, 0, 0]

        Crafting a SigreturnFrame that calls mprotect on i386

        >>> context.clear(arch='i386')
        >>> s = SigreturnFrame(kernel='i386')
        >>> unpack_many(bytes(s))
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 115, 0, 0, 123, 0]
        >>> assert len(s) == 80
        >>> s.eax = 125
        >>> s.ebx = 0x00601000
        >>> s.ecx = 0x1000
        >>> s.edx = 0x7
        >>> assert len(bytes(s)) == 80
        >>> unpack_many(bytes(s))
        [0, 0, 0, 0, 0, 0, 0, 0, 6295552, 7, 4096, 125, 0, 0, 0, 115, 0, 0, 123, 0]

        Crafting a SigreturnFrame that calls mprotect on ARM

        >>> s = SigreturnFrame(arch='arm')
        >>> unpack_many(bytes(s))
        [0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1073741840, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1447448577, 288]
        >>> s.r0 = 125
        >>> s.r1 = 0x00601000
        >>> s.r2 = 0x1000
        >>> s.r3 = 0x7
        >>> assert len(bytes(s)) == 240
        >>> unpack_many(bytes(s))
        [0, 0, 0, 0, 0, 6, 0, 0, 125, 6295552, 4096, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1073741840, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1447448577, 288]

        Crafting a SigreturnFrame that calls mprotect on MIPS

        >>> context.clear()
        >>> context.endian = "big"
        >>> s = SigreturnFrame(arch='mips')
        >>> unpack_many(bytes(s))
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        >>> s.v0 = 0x101d
        >>> s.a0 = 0x00601000
        >>> s.a1 = 0x1000
        >>> s.a2 = 0x7
        >>> assert len(bytes(s)) == 296
        >>> unpack_many(bytes(s))
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4125, 0, 0, 0, 6295552, 0, 4096, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

        Crafting a SigreturnFrame that calls mprotect on MIPSel

        >>> context.clear()
        >>> context.endian = "little"
        >>> s = SigreturnFrame(arch='mips')
        >>> unpack_many(bytes(s))
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        >>> s.v0 = 0x101d
        >>> s.a0 = 0x00601000
        >>> s.a1 = 0x1000
        >>> s.a2 = 0x7
        >>> assert len(bytes(s)) == 292
        >>> unpack_many(bytes(s))
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4125, 0, 0, 0, 6295552, 0, 4096, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

        Crafting a SigreturnFrame that calls mprotect on Aarch64

        >>> context.clear()
        >>> context.endian = "little"
        >>> s = SigreturnFrame(arch='aarch64')
        >>> unpack_many(bytes(s))
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1179680769, 528]
        >>> s.x8 = 0xe2
        >>> s.x0 = 0x4000
        >>> s.x1 = 0x1000
        >>> s.x2 = 0x7
        >>> assert len(bytes(s)) == 600
        >>> unpack_many(bytes(s))
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16384, 0, 4096, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 226, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1179680769, 528]
    """

    arch = None
    frame = None
    size  = 0
    _regs = []
    endian = None

    @LocalContext
    def __init__(self):
        if context.kernel is None and context.arch == 'i386':
            log.error("kernel architecture must be specified")

        self.arch = context.arch
        self.endian = context.endian
        self._regs = [self.registers[i] for i in sorted(self.registers.keys())]
        self.update({r:0 for r in self._regs})
        self.size = len(bytes(self))
        self.update(defaults[self.arch])

        if context.arch == 'i386' and context.kernel == 'amd64':
            self.update(defaults['i386_on_amd64'])

    def __setitem__(self, item, value):
        if item not in self._regs:
            log.error("Unknown register %r (not in %r)" % (item, self._regs))
        if self.arch == "arm" and item == "sp" and (value & 0x7):
            log.warn_once("ARM SP should be aligned to an 8-byte boundary")
        if self.arch == "aarch64" and item == "sp" and (value & 0xf):
            log.warn_once("AArch64 SP should be aligned to a 16-byte boundary")
        super(SigreturnFrame, self).__setitem__(item, value)

    def __setattr__(self, attr, value):
        if attr in SigreturnFrame.__dict__:
            super(SigreturnFrame, self).__setattr__(attr, value)
        else:
            self.set_regvalue(attr, value)

    def __getattr__(self, attr):
        return self[attr]

    def __bytes__(self):
        frame = b""
        with context.local(arch=self.arch):
            for register_offset in sorted(self.register_offsets):
                if len(frame) < register_offset:
                    frame += b"\x00"*(register_offset - len(frame))
                frame += pack(self[self.registers[register_offset]])
        return frame

    def __str__(self):
        return str(self.__bytes__())

    def __len__(self):
        return self.size

    def __flat__(self):
        return bytes(self)

    @property
    def registers(self):
        if self.arch == "mips" and self.endian == "little":
            return registers["mipsel"]
        return registers[self.arch]

    @property
    def register_offsets(self):
        if self.arch == "mips" and self.endian == "little":
            return registers["mipsel"]
        return registers[self.arch].keys()

    @property
    def arguments(self):
        # Skip the register used to hold the syscall number
        return ABI.syscall(arch=self.arch).register_arguments[1:]

    @arguments.setter
    def arguments(self, a):
        for arg, reg in zip(a, self.arguments):
            setattr(self, reg, arg)

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

    def set_regvalue(self, reg, val):
        """
        Sets a specific ``reg`` to a ``val``
        """
        self[reg] = val

    def get_spindex(self):
        return self._regs.index(stack_pointers[self.arch])
