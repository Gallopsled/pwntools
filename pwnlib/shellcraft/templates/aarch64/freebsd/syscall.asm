<%
  from pwnlib.shellcraft import aarch64, pretty
  from pwnlib.constants import Constant
  from pwnlib.abi import freebsd_aarch64_syscall as abi
  from six import text_type
%>
<%page args="syscall = None, arg0 = None, arg1 = None, arg2 = None, arg3 = None, arg4 = None, arg5 = None"/>
<%docstring>
Args: [syscall_number, \*args]
    Does a syscall

Any of the arguments can be expressions to be evaluated by :func:`pwnlib.constants.eval`.

Example:

    >>> print(shellcraft.aarch64.freebsd.syscall(11, 1, 'sp', 2, 0).rstrip())
        /* call syscall(11, 1, 'sp', 2, 0) */
        mov  x0, #1
        mov  x1, sp
        mov  x2, #2
        mov  x3, xzr
        mov  x8, #11
        svc 0
    >>> print(shellcraft.aarch64.freebsd.syscall('SYS_exit', 0).rstrip())
        /* call exit(0) */
        mov  x0, xzr
        mov  x8, #SYS_exit
        svc 0
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
    ${aarch64.setregs(regctx)}
%for arg in stack_args:
    ${aarch64.push(arg)}
%endfor
    svc 0
