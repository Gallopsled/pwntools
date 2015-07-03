<%
  from pwnlib.shellcraft import mips
  from pwnlib import constants
%>
<%page args="syscall = None, arg0 = None, arg1 = None, arg2 = None, arg3 = None, arg4 = None, arg5 = None, arg6 = None"/>
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

    for arg in [arg0, arg1, arg2, arg3, arg4, arg5, arg6]:
        if arg == None:
            args.append('?')
        else:
            args.append(repr(arg))
    while args and args[-1] == '?':
        args.pop()
    syscall_repr = syscall_repr % ', '.join(args)
    stack_regs = [arg4, arg5, arg6]
%>\
/* call ${syscall_repr} */
% if len(filter(lambda x: x is not None, stack_regs)) > 0:
    /* Be able to restore stack */
    sw $sp, -36($sp)

    % for i in range(len(stack_regs)):
        % if not stack_regs[i] is None:
            ${mips.mov('$at', stack_regs[i])}
            sw $at, ${-32 + 16 + i * 4}($sp)
        % endif
    % endfor
    add $sp, $sp, -32
% endif
% for dst, src in zip(['$a0', '$a1', '$a2', '$a3', '$v0'], [arg0, arg1, arg2, arg3, syscall]):
    % if src != None:
        ${mips.mov(dst, src)}
    % endif
% endfor
    syscall 0x42424
% if len(filter(lambda x: x is not None, stack_regs)) > 0:

    lw $sp, -4($sp)
% endif
