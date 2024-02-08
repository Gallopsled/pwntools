# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division

from pwnlib.context import LocalContext
from pwnlib.context import context


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

    def __init__(self, stack, regs, align, minimum):
        self.stack              = stack
        self.register_arguments = regs
        self.arg_alignment      = align
        self.stack_minimum      = minimum

    @staticmethod
    @LocalContext
    def default():
        if context.os == 'android':
            context.os = 'linux'

        return {
        (32, 'i386', 'linux'):  linux_i386,
        (64, 'aarch64', 'linux'): linux_aarch64,
        (64, 'amd64', 'linux'): linux_amd64,
        (32, 'arm', 'linux'):   linux_arm,
        (32, 'thumb', 'linux'):   linux_arm,
        (32, 'mips', 'linux'):   linux_mips,
        (32, 'powerpc', 'linux'): linux_ppc,
        (64, 'powerpc', 'linux'): linux_ppc64,
        (32, 'riscv32', 'linux'): linux_riscv32,
        (64, 'riscv64', 'linux'): linux_riscv64,
        (32, 'i386', 'freebsd'):  freebsd_i386,
        (64, 'aarch64', 'freebsd'): freebsd_aarch64,
        (64, 'amd64', 'freebsd'): freebsd_amd64,
        (32, 'arm', 'freebsd'):   freebsd_arm,
        (32, 'thumb', 'freebsd'):   freebsd_arm,
        (32, 'mips', 'freebsd'):   freebsd_mips,
        (32, 'powerpc', 'freebsd'): freebsd_ppc,
        (64, 'powerpc', 'freebsd'): freebsd_ppc64,
        (32, 'i386', 'windows'):  windows_i386,
        (64, 'amd64', 'windows'): windows_amd64,
        (64, 'amd64', 'darwin'): darwin_amd64,
        (64, 'aarch64', 'darwin'): darwin_aarch64,
        }[(context.bits, context.arch, context.os)]

    @staticmethod
    @LocalContext
    def syscall():
        if context.os == 'android':
            context.os = 'linux'

        return {
        (32, 'i386', 'linux'):  linux_i386_syscall,
        (64, 'amd64', 'linux'): linux_amd64_syscall,
        (64, 'aarch64', 'linux'): linux_aarch64_syscall,
        (32, 'arm', 'linux'):   linux_arm_syscall,
        (32, 'thumb', 'linux'):   linux_arm_syscall,
        (32, 'mips', 'linux'):   linux_mips_syscall,
        (64, 'aarch64', 'linux'):   linux_aarch64_syscall,
        (32, 'powerpc', 'linux'): linux_ppc_syscall,
        (64, 'powerpc', 'linux'): linux_ppc64_syscall,
        (32, 'riscv32', 'linux'): linux_riscv32_syscall,
        (64, 'riscv64', 'linux'): linux_riscv64_syscall,
        (32, 'i386', 'freebsd'):  freebsd_i386_syscall,
        (64, 'amd64', 'freebsd'): freebsd_amd64_syscall,
        (64, 'aarch64', 'freebsd'): freebsd_aarch64_syscall,
        (32, 'arm', 'freebsd'):   freebsd_arm_syscall,
        (32, 'thumb', 'freebsd'):   freebsd_arm_syscall,
        (32, 'mips', 'freebsd'):   freebsd_mips_syscall,
        (64, 'aarch64', 'freebsd'):   freebsd_aarch64_syscall,
        (32, 'powerpc', 'freebsd'): freebsd_ppc_syscall,
        (64, 'powerpc', 'freebsd'): freebsd_ppc64_syscall,
        (64, 'amd64', 'darwin'): darwin_amd64_syscall,
        (64, 'aarch64', 'darwin'): darwin_aarch64_syscall,
        }[(context.bits, context.arch, context.os)]

    @staticmethod
    @LocalContext
    def sigreturn():
        if context.os == 'android':
            context.os = 'linux'

        return {
        (32, 'i386', 'linux'):  linux_i386_sigreturn,
        (64, 'amd64', 'linux'): linux_amd64_sigreturn,
        (32, 'arm', 'linux'):   linux_arm_sigreturn,
        (32, 'thumb', 'linux'):   linux_arm_sigreturn,
        (64, 'aarch64', 'linux'):   linux_aarch64_sigreturn,
        (32, 'riscv32', 'linux'):   linux_riscv32_sigreturn,
        (64, 'riscv64', 'linux'):   linux_riscv64_sigreturn,
        (32, 'i386', 'freebsd'):  freebsd_i386_sigreturn,
        (64, 'amd64', 'freebsd'): freebsd_amd64_sigreturn,
        (32, 'arm', 'freebsd'):   freebsd_arm_sigreturn,
        (32, 'thumb', 'freebsd'):   freebsd_arm_sigreturn,
        (64, 'aarch64', 'freebsd'):   freebsd_aarch64_sigreturn,
        (64, 'amd64', 'darwin'):   darwin_amd64_sigreturn,
        (64, 'aarch64', 'darwin'):   darwin_aarch64_sigreturn,
        }[(context.bits, context.arch, context.os)]


class SyscallABI(ABI):
    """
    The syscall ABI treats the syscall number as the zeroth argument,
    which must be loaded into the specified register.
    """
    def __init__(self, *a, **kw):
        super(SyscallABI, self).__init__(*a, **kw)
        self.syscall_register = self.register_arguments[0]


class SigreturnABI(SyscallABI):
    """
    The sigreturn ABI is similar to the syscall ABI, except that
    both PC and SP are loaded from the stack.  Because of this, there
    is no 'return' slot necessary on the stack.
    """
    returns = False


# System V ABI used by many UNIXes
linux_i386   = ABI('esp', [], 4, 0)
linux_amd64  = ABI('rsp', ['rdi','rsi','rdx','rcx','r8','r9'], 8, 0)
linux_arm    = ABI('sp', ['r0', 'r1', 'r2', 'r3'], 8, 0)
linux_aarch64 = ABI('sp', ['x0', 'x1', 'x2', 'x3'], 16, 0)
linux_mips  = ABI('$sp', ['$a0','$a1','$a2','$a3'], 4, 0)
linux_ppc = ABI('sp', ['r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10'], 4, 0)
linux_ppc64 = ABI('sp', ['r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10'], 8, 0)
linux_riscv32 = ABI('sp', ['a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7'], 8, 0)
linux_riscv64 = ABI('sp', ['a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7'], 8, 0)

sysv_i386 = linux_i386
sysv_amd64 = linux_amd64
sysv_arm = linux_arm
sysv_aarch64 = linux_aarch64
sysv_mips = linux_mips
sysv_ppc = linux_ppc
sysv_ppc64 = linux_ppc64
sysv_riscv32 = linux_riscv32
sysv_riscv64 = linux_riscv64

# Docs: https://man7.org/linux/man-pages/man2/syscall.2.html
linux_i386_syscall = SyscallABI('esp', ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp'], 4, 0)
linux_amd64_syscall = SyscallABI('rsp', ['rax', 'rdi', 'rsi', 'rdx', 'r10', 'r8', 'r9'],   8, 0)
linux_arm_syscall = SyscallABI('sp', ['r7', 'r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6'], 4, 0)
linux_aarch64_syscall = SyscallABI('sp', ['x8', 'x0', 'x1', 'x2', 'x3', 'x4', 'x5'], 16, 0)
linux_mips_syscall  = SyscallABI('$sp', ['$v0','$a0','$a1','$a2','$a3'], 4, 0)
linux_ppc_syscall = SyscallABI('sp', ['r0', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9'], 4, 0)
linux_ppc64_syscall = SyscallABI('sp', ['r0', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8'], 8, 0)
linux_riscv32_syscall = SyscallABI('sp', ['a7', 'a0', 'a1', 'a2', 'a3', 'a4', 'a5'], 4, 0)
linux_riscv64_syscall = SyscallABI('sp', ['a7', 'a0', 'a1', 'a2', 'a3', 'a4', 'a5'], 8, 0)

linux_i386_sigreturn = SigreturnABI('esp', ['eax'], 4, 0)
linux_amd64_sigreturn = SigreturnABI('rsp', ['rax'], 8, 0)
linux_arm_sigreturn = SigreturnABI('sp', ['r7'], 4, 0)
linux_aarch64_sigreturn = SigreturnABI('sp', ['x8'], 16, 0)
linux_riscv32_sigreturn = SigreturnABI('sp', ['a7'], 4, 0)
linux_riscv64_sigreturn = SigreturnABI('sp', ['a7'], 8, 0)

sysv_i386_sigreturn = linux_i386_sigreturn
sysv_amd64_sigreturn = linux_amd64_sigreturn
sysv_arm_sigreturn = linux_arm_sigreturn
sysv_aarch64_sigreturn = linux_aarch64_sigreturn
sysv_riscv32_sigreturn = linux_riscv32_sigreturn
sysv_riscv64_sigreturn = linux_riscv64_sigreturn

freebsd_i386 = sysv_i386
freebsd_amd64 = sysv_amd64
freebsd_arm = sysv_arm
freebsd_aarch64 = sysv_aarch64
freebsd_mips = sysv_mips
freebsd_ppc = sysv_ppc
freebsd_ppc64 = sysv_ppc64

freebsd_i386_syscall   = SyscallABI('esp', ['eax'], 4, 0)
freebsd_amd64_syscall  = SyscallABI('rsp', ['rax','rdi','rsi','rdx','r10','r8','r9'], 8, 0)
freebsd_arm_syscall    = SyscallABI('sp', ['r7', 'r0', 'r1', 'r2', 'r3'], 8, 0)
freebsd_aarch64_syscall = SyscallABI('sp', ['x8', 'x0', 'x1', 'x2', 'x3'], 16, 0)
freebsd_mips_syscall  = SyscallABI('$sp', ['$v0','$a0','$a1','$a2','$a3'], 4, 0)
freebsd_ppc_syscall = SyscallABI('sp', ['r0', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10'], 4, 0)
freebsd_ppc64_syscall = SyscallABI('sp', ['r0', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10'], 8, 0)

freebsd_i386_sigreturn = sysv_i386_sigreturn
freebsd_amd64_sigreturn = sysv_amd64_sigreturn
freebsd_arm_sigreturn = sysv_arm_sigreturn
freebsd_aarch64_sigreturn = sysv_aarch64_sigreturn

windows_i386  = ABI('esp', [], 4, 0)
windows_amd64 = ABI('rsp', ['rcx','rdx','r8','r9'], 32, 32)

darwin_aarch64 = sysv_aarch64
darwin_aarch64_syscall = SyscallABI('sp', ['x16', 'x0', 'x1', 'x2', 'x3', 'x4', 'x5'], 16, 0)
darwin_aarch64_sigreturn = SigreturnABI('sp', ['x16'], 16, 0)

darwin_amd64 = sysv_amd64
darwin_amd64_syscall = SyscallABI('rsp', ['rax', 'rdi', 'rsi', 'rdx', 'r10', 'r8', 'r9'], 8, 0)
darwin_amd64_sigreturn = SigreturnABI('rsp', ['rax'], 8, 0)
