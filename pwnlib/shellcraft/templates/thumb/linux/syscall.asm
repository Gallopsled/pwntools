<%
  from pwnlib.shellcraft import thumb 
  from pwnlib.context import context as ctx # Ugly hack, mako will not let it be called context
%>


<%page args="syscall = None, arg0 = None, arg1 = None, arg2 = None, arg3 = None, arg4 = None, arg5 = None, arg6 = None"/>
<%docstring>
Args: [syscall_number, \*args]
    Does a syscall

Any of the arguments can be expressions to be evaluated by :func:`pwnlib.constants.eval`.

Example:

    >>> print shellcraft.thumb.linux.syscall(11, 1, 'sp', 2, 0).rstrip()
        /* call syscall(11, 1, 'sp', 2, 0) */
        mov r0, #1
        mov r1, sp
        mov r2, #2
        eor r3, r3
        mov r7, #11
        swi #1
    >>> print shellcraft.thumb.linux.syscall('SYS_exit', 0).rstrip()
        /* call exit(0) */
        movs r0, 1
        subs r0, 1
        mov r7, #SYS_exit
        swi #1
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
% for dst, src in zip(['r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7'], [arg0, arg1, arg2, arg3, arg4, arg5, arg6, syscall]):
  % if src != None:
    ${thumb.mov(dst, src)}
  % endif
% endfor
  swi #1
