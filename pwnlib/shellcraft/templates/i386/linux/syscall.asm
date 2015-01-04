<% from pwnlib.shellcraft import i386 %>\
<% from pwnlib.constants.linux import i386 as constants %>\
<%page args="syscall, arg0 = None, arg1 = None, arg2 = None, arg3 = None, arg4 = None"/>
<%docstring>
Args: [syscall_number, *args]
    Does a syscall
</%docstring>
<%
  append_cdq = False
  if isinstance(syscall, (str, unicde)) and syscall.startswith('SYS_'):
      syscall_repr = syscall[4:] + "(%s)"
      args = []
  else:
      syscall_repr = 'syscall(%s)'
      args = [repr(syscall)]

  for arg in [arg0, arg1, arg2, arg3, arg4]:
      if arg == None:
          args.append('?')
      else:
          args.append(repr(arg))
  while args and args[-1] == '?':
      args.pop()
  syscall_repr = syscall_repr % ', '.join(args)
%>\
    /* call ${syscall_repr} */
% for dst, src in zip(['ebx', 'ecx', 'edx', 'esi', 'edi', 'eax'], [arg0, arg1, arg2, arg3, arg4, syscall]):
  % if dst == 'edx' and src == 0:
    <% append_cdq = True %>\
  % elif src != None:
    <%
      if isinstance(src, (str, unicode)):
          src = getattr(constants, src, src)
    %>\
    ${i386.mov(dst, src)}
  % endif
% endfor
% if append_cdq:
    cdq /* Set edx to 0, eax is known to be positive */
% endif
    int 0x80
