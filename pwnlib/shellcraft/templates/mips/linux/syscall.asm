<%
  from pwnlib.shellcraft import mips
  from pwnlib.context import context as ctx # Ugly hack, mako will not let it be called context
%>


<%page args="syscall = None, arg0 = None, arg1 = None, arg2 = None, arg3 = None, arg4 = None, arg5 = None, arg6 = None"/>
<%docstring>
Args: [syscall_number, \*args]
    Does a syscall

Any of the arguments can be expressions to be evaluated by :func:`pwnlib.constants.eval`.

Example:

    >>> print shellcraft.mips.linux.syscall(11, 1, 'sp', 2, 0).rstrip()
        /* call syscall(11, 1, 'sp', 2, 0) */
        /* Set a0 = 1 = 0x1 */
        li $a0, 1
        move $a1, $sp
        /* Set a2 = 2 = 0x2 */
        li $a2, #2
        /* Set a3 = 0 = 0x0 */
        xor $a3, $a3, $a3
        /* Set a7 = 11 = 0xb */
        li $v0, 11
        syscall
    >>> print shellcraft.mips.linux.syscall('SYS_exit', 0).rstrip()
        /* call exit(0) */
        /* Set a0 = 0 = 0x0 */
        xor $a0, $a0, $a0
        /* Set v0 = (SYS_exit) = 0xfa1 */
        move $v0, (SYS_exit)
        syscall
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
%>\
    /* call ${syscall_repr} */
% for dst, src in zip(['a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'v0'], [arg0, arg1, arg2, arg3, arg4, arg5, arg6, syscall]):
  % if src != None:
    ${mips.mov(dst, src)}
  % endif
% endfor
  syscall
