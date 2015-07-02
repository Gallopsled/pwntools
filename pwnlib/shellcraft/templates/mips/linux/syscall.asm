<%
  from pwnlib.shellcraft import mips
%>
<%page args="syscall = None, arg0 = None, arg1 = None, arg2 = None, arg3 = None"/>
<%docstring>
Args: [syscall_number, \*args]
    Does a syscall

Any of the arguments can be expressions to be evaluated by :func:`pwnlib.constants.eval`.
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

    for arg in [arg0, arg1, arg2, arg3]:
        if arg == None:
            args.append('?')
        else:
            args.append(repr(arg))
    while args and args[-1] == '?':
        args.pop()
    syscall_repr = syscall_repr % ', '.join(args)
%>\
/* call ${syscall_repr} */
% for dst, src in zip(['$a0', '$a1', '$a2', '$a3', '$v0'], [arg0, arg1, arg2, arg3, syscall]):
    % if src != None:
        ${mips.mov(dst, src)}
    % endif
% endfor
syscall 0x42424
