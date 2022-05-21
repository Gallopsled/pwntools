<%
  from pwnlib.shellcraft import i386, pretty
  from pwnlib.constants import Constant
  from pwnlib.abi import freebsd_i386_syscall as abi
  from six import text_type
%>
<%page args="syscall = None, arg0 = None, arg1 = None, arg2 = None, arg3 = None, arg4 = None, arg5 = None"/>
<%docstring>
Args: [syscall_number, \*args]
    Does a syscall

Any of the arguments can be expressions to be evaluated by :func:`pwnlib.constants.eval`.

Example:

        >>> print(pwnlib.shellcraft.i386.freebsd.syscall('SYS_execve', 1, 'esp', 2, 0).rstrip())
            /* call execve(1, 'esp', 2, 0) */
            push SYS_execve /* 0x3b */
            pop eax
            /* push 0 */
            push 1
            dec byte ptr [esp]
            /* push 2 */
            push 2
            push esp
            /* push 1 */
            push 1
            /* push padding DWORD */
            push eax
            int 0x80
        >>> print(pwnlib.shellcraft.i386.freebsd.syscall('SYS_execve', 2, 1, 0, 20).rstrip())
            /* call execve(2, 1, 0, 0x14) */
            push SYS_execve /* 0x3b */
            pop eax
            /* push 0x14 */
            push 0x14
            /* push 0 */
            push 1
            dec byte ptr [esp]
            /* push 1 */
            push 1
            /* push 2 */
            push 2
            /* push padding DWORD */
            push eax
            int 0x80
        >>> print(pwnlib.shellcraft.i386.freebsd.syscall().rstrip())
            /* call syscall() */
            /* setregs noop */
            /* push padding DWORD */
            push eax
            int 0x80
        >>> print(pwnlib.shellcraft.i386.freebsd.syscall('eax', 'ebx', 'ecx').rstrip())
            /* call syscall('eax', 'ebx', 'ecx') */
            /* setregs noop */
            push ecx
            push ebx
            /* push padding DWORD */
            push eax
            int 0x80
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
    ${i386.setregs(regctx)}
%for arg in stack_args:
    ${i386.push(arg)}
%endfor
    /* push padding DWORD */
    push eax
    int 0x80
