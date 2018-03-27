<%
  from pwnlib.shellcraft import mips, pretty
  from pwnlib.constants import Constant
  from pwnlib.abi import linux_mips_syscall as abi
  from six import text_type
%>
<%page args="syscall = None, arg0 = None, arg1 = None, arg2 = None, arg3 = None, arg4=None, arg5=None"/>
<%docstring>
Args: [syscall_number, \*args]
    Does a syscall

Any of the arguments can be expressions to be evaluated by :func:`pwnlib.constants.eval`.

Example:

        >>> print(pwnlib.shellcraft.mips.linux.syscall('SYS_execve', 1, '$sp', 2, 0).rstrip())
            /* call execve(1, '$sp', 2, 0) */
            li $t9, ~1
            not $a0, $t9
            add $a1, $sp, $0 /* mov $a1, $sp */
            li $t9, ~2
            not $a2, $t9
            slti $a3, $zero, 0xFFFF /* $a3 = 0 */
            ori $v0, $zero, SYS_execve
            syscall 0x40404
        >>> print(pwnlib.shellcraft.mips.linux.syscall('SYS_execve', 2, 1, 0, 20).rstrip())
            /* call execve(2, 1, 0, 0x14) */
            li $t9, ~2
            not $a0, $t9
            li $t9, ~1
            not $a1, $t9
            slti $a2, $zero, 0xFFFF /* $a2 = 0 */
            li $t9, ~0x14
            not $a3, $t9
            ori $v0, $zero, SYS_execve
            syscall 0x40404
        >>> print(pwnlib.shellcraft.mips.linux.syscall().rstrip())
            /* call syscall() */
            syscall 0x40404
        >>> print(pwnlib.shellcraft.mips.linux.syscall('$v0', '$a0', '$a1').rstrip())
            /* call syscall('$v0', '$a0', '$a1') */
            /* setregs noop */
            syscall 0x40404
        >>> print(pwnlib.shellcraft.mips.linux.syscall('$a3', None, None, 1).rstrip())
            /* call syscall('$a3', ?, ?, 1) */
            li $t9, ~1
            not $a2, $t9
            sw $a3, -4($sp) /* mov $v0, $a3 */
            lw $v0, -4($sp)
            syscall 0x40404
        >>> print(pwnlib.shellcraft.mips.linux.syscall(
        ...               'SYS_mmap2', 0, 0x1000,
        ...               'PROT_READ | PROT_WRITE | PROT_EXEC',
        ...               'MAP_PRIVATE | MAP_ANONYMOUS',
        ...               -1, 0).rstrip())
            /* call mmap2(0, 0x1000, 'PROT_READ | PROT_WRITE | PROT_EXEC', 'MAP_PRIVATE | MAP_ANONYMOUS', -1, 0) */
            slti $a0, $zero, 0xFFFF /* $a0 = 0 */
            li $t9, ~0x1000
            not $a1, $t9
            li $t9, ~(PROT_READ | PROT_WRITE | PROT_EXEC) /* 7 */
            not $a2, $t9
            ori $a3, $zero, (MAP_PRIVATE | MAP_ANONYMOUS)
            ori $v0, $zero, SYS_mmap2
            syscall 0x40404
        >>> print(pwnlib.shellcraft.open('/home/pwn/flag').rstrip())
            /* open(file='/home/pwn/flag', oflag=0, mode=0) */
            /* push '/home/pwn/flag\x00' */
            li $t1, 0x6d6f682f
            sw $t1, -16($sp)
            li $t1, 0x77702f65
            sw $t1, -12($sp)
            li $t1, 0x6c662f6e
            sw $t1, -8($sp)
            ori $t1, $zero, 26465
            sw $t1, -4($sp)
            addiu $sp, $sp, -16
            add $a0, $sp, $0 /* mov $a0, $sp */
            slti $a1, $zero, 0xFFFF /* $a1 = 0 */
            slti $a2, $zero, 0xFFFF /* $a2 = 0 */
            /* call open() */
            ori $v0, $zero, SYS_open
            syscall 0x40404
</%docstring>
<%
  append_cdq = False
  if isinstance(syscall, (str, text_type, Constant)) and str(syscall).startswith('SYS_'):
      syscall_repr = str(syscall)[4:] + "(%s)"
      args = []
  else:
      syscall_repr = 'syscall(%s)'
      if syscall == None:
          args = ['?']
      else:
          args = [repr(syscall)]

  for arg in [arg0, arg1, arg2, arg3, arg4, arg5]:
      if arg == None:
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
    ${mips.setregs(regctx)}
%endif
    syscall 0x40404
