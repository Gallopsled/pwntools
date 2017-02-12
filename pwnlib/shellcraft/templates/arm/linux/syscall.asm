<%
  from pwnlib.shellcraft import arm
  from pwnlib.constants import eval
  from pwnlib.abi import linux_arm_syscall as abi
%>
<%page args="syscall = None, arg0 = None, arg1 = None, arg2 = None, arg3 = None, arg4 = None, arg5 = None, arg6 = None"/>
<%docstring>
Args: [syscall_number, \*args]
    Does a syscall

Any of the arguments can be expressions to be evaluated by :func:`pwnlib.constants.eval`.

Example:

    >>> print shellcraft.arm.linux.syscall(11, 1, 'sp', 2, 0).rstrip()
        /* call syscall(11, 1, 'sp', 2, 0) */
        mov  r0, #1
        mov  r1, sp
        mov  r2, #2
        eor  r3, r3 /* 0 (#0) */
        mov  r7, #0xb
        svc  0
    >>> print shellcraft.arm.linux.syscall('SYS_exit', 0).rstrip()
        /* call exit(0) */
        eor  r0, r0 /* 0 (#0) */
        mov  r7, #SYS_exit /* 1 */
        svc  0
    >>> print pwnlib.shellcraft.open('/home/pwn/flag').rstrip()
        /* open(file='/home/pwn/flag', oflag=0, mode=0) */
        /* push '/home/pwn/flag\x00A' */
        movw r7, #0x41006761 & 0xffff
        movt r7, #0x41006761 >> 16
        push {r7}
        movw r7, #0x6c662f6e & 0xffff
        movt r7, #0x6c662f6e >> 16
        push {r7}
        movw r7, #0x77702f65 & 0xffff
        movt r7, #0x77702f65 >> 16
        push {r7}
        movw r7, #0x6d6f682f & 0xffff
        movt r7, #0x6d6f682f >> 16
        push {r7}
        mov  r0, sp
        eor  r1, r1 /* 0 (#0) */
        eor  r2, r2 /* 0 (#0) */
        /* call open() */
        mov  r7, #SYS_open /* 5 */
        svc  0
</%docstring>
<%
  if isinstance(syscall, (str, unicode)) and syscall.startswith('SYS_'):
      syscall_repr = syscall[4:] + "(%s)"
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
          args.append(repr(arg))
  while args and args[-1] == '?':
      args.pop()
  syscall_repr = syscall_repr % ', '.join(args)

  registers = abi.register_arguments
  arguments = [syscall, arg0, arg1, arg2, arg3, arg4, arg5]
  regctx    = dict(zip(registers, arguments))
%>\
    /* call ${syscall_repr} */
%if any(arguments):
    ${arm.setregs(regctx)}
%endif
    svc  0
