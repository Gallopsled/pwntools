<%
  from pwnlib.shellcraft import aarch64
  from pwnlib.constants import eval
  from pwnlib.abi import linux_aarch64_syscall as abi
%>
<%page args="syscall = None, arg0 = None, arg1 = None, arg2 = None, arg3 = None, arg4 = None, arg5 = None, arg6 = None"/>
<%docstring>
Args: [syscall_number, \*args]
    Does a syscall

Any of the arguments can be expressions to be evaluated by :func:`pwnlib.constants.eval`.

Example:

    >>> print shellcraft.aarch64.linux.syscall(11, 1, 'sp', 2, 0).rstrip()
        /* call syscall(11, 1, 'sp', 2, 0) */
        mov  x0, #1
        mov  x1, sp
        mov  x2, #2
        mov  x3, xzr
        mov  x8, #11
        svc 0
    >>> print shellcraft.aarch64.linux.syscall('SYS_exit', 0).rstrip()
        /* call exit(0) */
        mov  x0, xzr
        mov  x8, #SYS_exit
        svc 0
    >>> print pwnlib.shellcraft.open('/home/pwn/flag').rstrip()
        /* open(file='/home/pwn/flag', oflag=0, mode=0) */
        /* push '/home/pwn/flag\x00\x00' */
        sub sp, sp, #16
        /* Set x0 = 8606431000579237935 = 0x77702f656d6f682f */
        mov  x0, #26671
        movk x0, #28015, lsl #16
        movk x0, #12133, lsl #0x20
        movk x0, #30576, lsl #0x30
        /* Set x1 = 113668128124782 = 0x67616c662f6e */
        mov  x1, #12142
        movk x1, #27750, lsl #16
        movk x1, #26465, lsl #0x20
        stp x0, x1, [sp, #16 * 0]
        mov  x0, sp
        mov  x1, xzr
        mov  x2, xzr
        /* call open() */
        mov  x8, #SYS_open
        svc 0
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
    ${aarch64.setregs(regctx)}
%endif
    svc 0
