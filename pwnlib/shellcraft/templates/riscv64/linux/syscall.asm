<%
  from pwnlib.shellcraft import riscv64, pretty
  from pwnlib.constants import Constant
  from pwnlib.abi import linux_riscv64_syscall as abi
  from six import text_type
%>
<%page args="syscall = None, arg0 = None, arg1 = None, arg2 = None, arg3 = None, arg4=None, arg5=None"/>
<%docstring>
Args: [syscall_number, \*args]
    Does a syscall

Any of the arguments can be expressions to be evaluated by :func:`pwnlib.constants.eval`.

Example:

        >>> print(pwnlib.shellcraft.riscv64.linux.syscall('SYS_execve', 1, 'sp', 2, 0).rstrip())
            /* call execve(1, 'sp', 2, 0) */
            c.li a0, 1
            c.mv a1, sp
            c.li a2, 2
            c.li a3, 0
            /* mv a7, 0xdd */
            xori a7, zero, 0x722
            xori a7, a7, 0x7ff
            ecall
        >>> print(pwnlib.shellcraft.riscv64.linux.syscall('SYS_execve', 2, 1, 0, 20).rstrip())
            /* call execve(2, 1, 0, 0x14) */
            c.li a0, 2
            c.li a1, 1
            c.li a2, 0
            c.li a3, 0x14
            /* mv a7, 0xdd */
            xori a7, zero, 0x722
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
            c.li a2, 1
            c.mv a7, a3
            ecall
        >>> print(pwnlib.shellcraft.riscv64.linux.syscall(
        ...               'SYS_mmap', 0, 0x1000,
        ...               'PROT_READ | PROT_WRITE | PROT_EXEC',
        ...               'MAP_PRIVATE',
        ...               -1, 0).rstrip())
            /* call mmap(0, 0x1000, 'PROT_READ | PROT_WRITE | PROT_EXEC', 'MAP_PRIVATE', -1, 0) */
            c.li a0, 0
            c.lui a1, 1 /* mv a1, 0x1000 */
            c.li a2, 7
            c.li a3, 2
            c.li a4, 0xffffffffffffffff
            c.li a5, 0
            /* mv a7, 0xde */
            xori a7, zero, 0x721
            xori a7, a7, 0x7ff
            ecall
        >>> print(pwnlib.shellcraft.openat('AT_FDCWD', '/home/pwn/flag').rstrip())
            /* openat(fd='AT_FDCWD', file='/home/pwn/flag', oflag=0) */
            /* push b'/home/pwn/flag\x00' */
            li t4, 0x77702f656d6f682f
            sd t4, -16(sp)
            li t4, 0x67616c662f6e
            sd t4, -8(sp)
            addi sp, sp, -16
            c.mv a1, sp
            xori a0, zero, 0xffffffffffffff9c
            c.li a2, 0
            /* call openat() */
            /* mv a7, 0x38 */
            xori a7, zero, 0x7c7
            xori a7, a7, 0x7ff
            ecall
</%docstring>
<%
  if isinstance(syscall, (str, text_type, Constant)) and str(syscall).startswith('SYS_'):
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
