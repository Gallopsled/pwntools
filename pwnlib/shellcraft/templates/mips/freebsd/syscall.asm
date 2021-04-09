<%
  from pwnlib.shellcraft import mips, pretty
  from pwnlib.constants import Constant
  from pwnlib.abi import freebsd_mips_syscall as abi
  from six import text_type
%>
<%page args="syscall = None, arg0 = None, arg1 = None, arg2 = None, arg3 = None, arg4 = None, arg5 = None"/>
<%docstring>
Args: [syscall_number, \*args]
    Does a syscall

Any of the arguments can be expressions to be evaluated by :func:`pwnlib.constants.eval`.

Example:

        >>> print(pwnlib.shellcraft.mips.freebsd.syscall('SYS_execve', 1, '$sp', 2, 0).rstrip())
            /* call execve(1, '$sp', 2, 0) */
            li $t9, ~1
            not $a0, $t9
            add $a1, $sp, $0 /* mov $a1, $sp */
            li $t9, ~2
            not $a2, $t9
            slti $a3, $zero, 0xFFFF /* $a3 = 0 */
            li $t9, ~SYS_execve /* 0x3b */
            not $v0, $t9
            syscall 0x40404
        >>> print(pwnlib.shellcraft.mips.freebsd.syscall('SYS_execve', 2, 1, 0, 20).rstrip())
            /* call execve(2, 1, 0, 0x14) */
            li $t9, ~2
            not $a0, $t9
            li $t9, ~1
            not $a1, $t9
            slti $a2, $zero, 0xFFFF /* $a2 = 0 */
            li $t9, ~0x14
            not $a3, $t9
            li $t9, ~SYS_execve /* 0x3b */
            not $v0, $t9
            syscall 0x40404
        >>> print(pwnlib.shellcraft.mips.freebsd.syscall().rstrip())
            /* call syscall() */
            /* setregs noop */
            syscall 0x40404
        >>> print(pwnlib.shellcraft.mips.freebsd.syscall('$v0', '$a0', '$a1').rstrip())
            /* call syscall('$v0', '$a0', '$a1') */
            /* setregs noop */
            syscall 0x40404
        >>> print(pwnlib.shellcraft.mips.freebsd.syscall('$a3', None, None, 1).rstrip())
            /* call syscall('$a3', ?, ?, 1) */
            li $t9, ~1
            not $a0, $t9
            sw $a3, -4($sp) /* mov $v0, $a3 */
            lw $v0, -4($sp)
            syscall 0x40404
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

  registers  = abi.register_arguments
  arguments  = [syscall, arg0, arg1, arg2, arg3, arg4, arg5]
  arguments  = iter(filter(lambda arg: arg is not None, arguments))
  regctx     = dict(zip(registers, arguments))
  stack_args = reversed(list(arguments)) # push remaining args on stack in reverse order
%>\
    /* call ${syscall_repr} */
    ${mips.setregs(regctx)}
%for arg in stack_args:
    ${mips.push(arg)}
%endfor
    syscall 0x40404
