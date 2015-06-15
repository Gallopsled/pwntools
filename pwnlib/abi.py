# -*- coding: utf-8 -*-
from .context import context, LocalContext

class ABI(object):
    """
    Encapsulates information about a calling convention.
    """
    #: List or registers which should be filled with arguments before
    #: spilling onto the stack.
    register_arguments = []

    #: Minimum alignment of the stack.
    #: The value used is min(context.bytes, stack_alignment)
    #: This is necessary as Windows x64 frames must be 32-byte aligned.
    #: "Alignment" is considered with respect to the last argument on the stack.
    arg_alignment    = 1

    #: Minimum number of stack slots used by a function call
    #: This is necessary as Windows x64 requires using 4 slots on the stack
    stack_minimum      = 0

    #: Indicates that this ABI returns to the next address on the slot
    returns            = True

    def __init__(self, regs, align, minimum):
        self.register_arguments = regs
        self.arg_alignment      = align
        self.stack_minimum      = minimum

    @staticmethod
    @LocalContext
    def default():
        return {
        (32, 'i386', 'linux'):  linux_i386,
        (64, 'amd64', 'linux'): linux_amd64,
        (32, 'arm', 'linux'):   linux_arm,
        (32, 'i386', 'windows'):  windows_i386,
        (64, 'amd64', 'windows'): windows_amd64,
        }[(context.bits, context.arch, context.os)]

    @staticmethod
    @LocalContext
    def syscall():
        return {
        (32, 'i386', 'linux'):  linux_i386_syscall,
        (64, 'amd64', 'linux'): linux_amd64_syscall,
        (32, 'arm', 'linux'):   linux_arm_syscall,
        }[(context.bits, context.arch, context.os)]

    @staticmethod
    @LocalContext
    def sigreturn():
        return {
        (32, 'i386', 'linux'):  linux_i386_sigreturn,
        (64, 'amd64', 'linux'): linux_amd64_sigreturn,
        (32, 'arm', 'linux'):   linux_arm_sigreturn,
        }[(context.bits, context.arch, context.os)]

class SyscallABI(ABI):
    """
    The syscall ABI treats the syscall number as the zeroth argument,
    which must be loaded into the specified register.
    """
    def __init__(self, register_arguments, *a, **kw):
        super(SyscallABI, self).__init__(register_arguments, *a, **kw)
        self.syscall_register = register_arguments[0]

class SigreturnABI(SyscallABI):
    """
    The sigreturn ABI is similar to the syscall ABI, except that
    both PC and SP are loaded from the stack.  Because of this, there
    is no 'return' slot necessary on the stack.
    """
    returns = False


linux_i386   = ABI([], 4, 0)
linux_amd64  = ABI(['rdi','rsi','rdx','rcx','r8','r9'], 8, 0)
linux_arm    = ABI(['r0', 'r1', 'r2', 'r3'], 8, 0)

linux_i386_syscall = SyscallABI(['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp'], 4, 0)
linux_amd64_syscall = SyscallABI(['rax','rdi', 'rsi', 'rdx', 'r10', 'r8', 'r9'],   8, 0)
linux_arm_syscall   = SyscallABI(['r7', 'r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6'], 4, 0)

linux_i386_sigreturn = SigreturnABI(['eax'], 4, 0)
linux_amd64_sigreturn = SigreturnABI(['rax'], 4, 0)
linux_arm_sigreturn = SigreturnABI(['r7'], 4, 0)

windows_i386  = ABI([], 4, 0)
windows_amd64 = ABI(['rcx','rdx','r8','r9'], 32, 32)

# Fake ABIs used by SROP
linux_i386_srop = ABI(['eax'], 4, 0)
linux_amd64_srop = ABI(['rax'], 4, 0)
linux_arm_srop = ABI(['r7'], 4, 0)


''' === OLD CODE ===
class AbiCall(Call):
    """
    Encapsulates ABI-specific information about a function call, which is
    to be executed with ROP.
    """
    #: Mapping of registers to the values to which they should be set, before
    #: $pc is set to ``addr``.
    registers = {}

    #: List of values which must appear in-order on the stack, including all
    #: padding required by the ABI (e.g. Windows x64 requires a minimum of 32 bytes)
    stack = []

    def __new__(cls, *a, **kw):
        # Allow explicit creation of subclasses
        if cls != AbiCall:
            return super(AbiCall, cls).__new__(cls, *a, **kw)

        # Do not allow explicit creation of AbiCall.
        # Default to the best choice.
        abis = {
            ('i386',32,'linux'): x86LinuxAbiCall,
            ('amd64',64,'linux'): amd64LinuxAbiCall,
            ('arm',32,'linux'): armLinuxAbiCall
        }

        key = (context.arch, context.bits, context.os)

        if key not in abis:
            log.error("Don't know how to make ROP calls for %r" % (key,))

        return super(AbiCall, cls).__new__(abis[key], *a, **kw)

    def __init__(self, name, target, args):
        super(AbiCall, self).__init__(name, target, args)
        self.registers = {}
        self.stack     = []

        self.build()


class StackAdjustingAbiCall(AbiCall):
    """
    Encapsulates information about a calling convention which
    may capture arguments on the stack, and as such the stack
    pointer must be adjusted in order to continue ROP execution.

    This functionality is separated out from the normal ABI call
    so that optimizations can be performed on the last call in
    the stack if there are no arguments.
    """
    def build(self, addr = None):
        self.stack.append(StackAdjustment())

class x86LinuxAbiCall(StackAdjustingAbiCall):
    def build(self, addr = None):
        super(x86LinuxAbiCall, self).build()

        self.stack.extend(self.args)

class amd64LinuxAbiCall(StackAdjustingAbiCall):
    def build(self, addr = None):
        super(amd64LinuxAbiCall, self).build()

        registers = ['rdi','rsi','rdx','rcx','r8','r9']

        for reg, arg in zip(registers, self.args):
            self.registers[reg] = arg

        self.stack.extend(self.args[len(registers):])

class armLinuxAbiCall(StackAdjustingAbiCall):
    def build(self, addr = None):
        super(armLinuxAbiCall, self).build()

        registers = ['r0','r1','r2','r3']
        args      = list(self.args)

        for reg, arg in zip(registers, args):
            self.registers[reg] = arg

        self.stack.extend(self.args[len(registers):])

class x86SysretCall(x86LinuxAbiCall):
    def build(self, addr = None):
        super(x86SysretCall, self).build()
        self.stack = list(self.args)
        self.regs  = {'eax': constants.i386.SYS_sigreturn}

class x64SysretCall(AbiCall):
    def build(self, addr = None):
        super(x64SysretCall, self).build()
        self.stack = list(self.args)
        self.regs  = {'rax': constants.amd64.SYS_sigreturn}
'''
