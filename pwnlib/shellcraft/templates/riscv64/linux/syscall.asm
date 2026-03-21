<%
  from pwnlib.shellcraft import riscv64, pretty
  from pwnlib.constants import Constant
  from pwnlib.abi import linux_riscv64_syscall as abi
%>
<%page args="syscall = None, arg0 = None, arg1 = None, arg2 = None, arg3 = None, arg4=None, arg5=None"/>
<%docstring>
Args: [syscall_number, \*args]
    Does a syscall

Any of the arguments can be expressions to be evaluated by :func:`pwnlib.constants.eval`.

Example:

        >>> print(pwnlib.shellcraft.riscv64.linux.syscall('SYS_execve', 1, 'sp', 2, 0).rstrip())
            /* call execve(1, 'sp', 2, 0) */
            sltiu a0, zero, 0x7ff | 1
            sra a1, sp, zero
            xori a2, zero, 0x7ff ^ 2
            xori a2, a2, 0x7ff
            xor a3, t6, t6
            xori a7, zero, 0x7ff ^ SYS_execve /* 0xdd */
            xori a7, a7, 0x7ff
            ecall
        >>> print(pwnlib.shellcraft.riscv64.linux.syscall('SYS_execve', 2, 1, 0, 20).rstrip())
            /* call execve(2, 1, 0, 0x14) */
            xori a0, zero, 0x7ff ^ 2
            xori a0, a0, 0x7ff
            sltiu a1, zero, 0x7ff | 1
            xor a2, t6, t6
            xori a3, zero, 0x7ff ^ 0x14
            xori a3, a3, 0x7ff
            xori a7, zero, 0x7ff ^ SYS_execve /* 0xdd */
            xori a7, a7, 0x7ff
            ecall
        >>> print(pwnlib.shellcraft.riscv64.linux.syscall().rstrip())
            /* call syscall() */
            ecall
        >>> print(pwnlib.shellcraft.riscv64.linux.syscall('a7', 'a0', 'a1').rstrip())
            /* call syscall('a7', 'a0', 'a1') */
            /* setregs noop */
            ecall
        >>> print(pwnlib.shellcraft.riscv64.linux.syscall('a3', None, None, 1).rstrip())
            /* call syscall('a3', ?, ?, 1) */
            sltiu a2, zero, 0x7ff | 1
            sra a7, a3, zero
            ecall
        >>> print(pwnlib.shellcraft.riscv64.linux.syscall(
        ...               'SYS_mmap', 0, 0x1000,
        ...               'PROT_READ | PROT_WRITE | PROT_EXEC',
        ...               'MAP_PRIVATE',
        ...               -1, 0).rstrip())
            /* call mmap(0, 0x1000, 'PROT_READ | PROT_WRITE | PROT_EXEC', 'MAP_PRIVATE', -1, 0) */
            xor a0, t6, t6
            li a1, 0x1000
            xori a2, zero, 0x7ff ^ (PROT_READ | PROT_WRITE | PROT_EXEC) /* 7 */
            xori a2, a2, 0x7ff
            xori a3, zero, 0x7ff ^ MAP_PRIVATE /* 2 */
            xori a3, a3, 0x7ff
            xori a4, zero, -1
            xor a5, t6, t6
            xori a7, zero, 0x7ff ^ SYS_mmap /* 0xde */
            xori a7, a7, 0x7ff
            ecall
        >>> print(pwnlib.shellcraft.openat('AT_FDCWD', '/home/pwn/flag').rstrip())
            /* openat(fd='AT_FDCWD', file='/home/pwn/flag', oflag=0) */
            /* push b'/home/pwn/flag\x00' */
            lui t4, 0xfffff & ((0x77702f65 >> 12) + 1)
            xori t4, t4, 0x7ff & 0x77702f65
            addi t4, t4, -0x800
            lui t6, 0xfffff & ((0x6d6f682f >> 12) + 1)
            xori t6, t6, 0x7ff & 0x6d6f682f
            addi t6, t6, -0x800
            slli t4, t4, 0x20
            xor t4, t4, t6
            sd t4, -16(sp)
            lui t4, 0xfffff & (~0x6761 >> 12)
            xori t4, t4, ~0x7ff | 0x6761
            addi t4, t4, -0x800
            lui t6, 0xfffff & ((0x6c662f6e >> 12) + 1)
            xori t6, t6, 0x7ff & 0x6c662f6e
            addi t6, t6, -0x800
            slli t4, t4, 0x20
            xor t4, t4, t6
            sd t4, -8(sp)
            addi sp, sp, -16
            sra a1, sp, zero
            xori a0, zero, AT_FDCWD /* -0x64 */
            xor a2, t6, t6
            /* call openat() */
            xori a7, zero, 0x7ff ^ SYS_openat /* 0x38 */
            xori a7, a7, 0x7ff
            ecall
</%docstring>
<%
  if isinstance(syscall, (str, Constant)) and str(syscall).startswith('SYS_'):
      syscall_repr = str(syscall)[4:] + "(%s)"
      args = []
  else:
      syscall_repr = 'syscall(%s)'
      if syscall is None:
          args = ['?']
      else:
          args = [pretty(syscall, False)]

  for arg in [arg0, arg1, arg2, arg3, arg4, arg5]:
      if arg is None:
          args.append('?')
      else:
          args.append(pretty(arg, False))
  while args and args[-1] == '?':
      args.pop()
  syscall_repr = syscall_repr % ', '.join(args)

  registers = abi.register_arguments
  arguments = [syscall, arg0, arg1, arg2, arg3, arg4, arg5]
  regctx    = dict(zip(registers, arguments))
%>\
    /* call ${syscall_repr} */
%if any(a is not None for a in arguments):
    ${riscv64.setregs(regctx)}
%endif
    ecall
