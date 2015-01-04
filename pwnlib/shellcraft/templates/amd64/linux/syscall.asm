<% from pwnlib.shellcraft import amd64 %>\
<% from pwnlib.constants.linux import amd64 as constants %>\
<%page args="syscall = None, arg0 = None, arg1 = None, arg2 = None, arg3 = None, arg4 = None, arg5 = None"/>
<%docstring>
Args: [syscall_number, *args]
    Does a syscall

Example:

        >>> print pwnlib.shellcraft.amd64.linux.syscall('SYS_execve', 1, 'rsp', 2, 0).rstrip()
            /* call execve(1, 'rsp', 2, 0) */
            push 0x1
            pop rdi
            mov rsi, rsp
            push 0x2
            pop rdx
            xor r10d, r10d
            push 0x3b
            pop rax
            syscall
        >>> print pwnlib.shellcraft.amd64.linux.syscall('SYS_execve', 2, 1, 0, -1).rstrip()
            /* call execve(2, 1, 0, -1) */
            push 0x2
            pop rdi
            push 0x1
            pop rsi
            push -1
            pop r10
            push 0x3b
            pop rax
            cdq /* Set rdx to 0, rax is known to be positive */
            syscall
        >>> print pwnlib.shellcraft.amd64.linux.syscall().rstrip()
            /* call syscall() */
            syscall
        >>> print pwnlib.shellcraft.amd64.linux.syscall('rax', 'rdi', 'rsi').rstrip()
            /* call syscall('rax', 'rdi', 'rsi') */
            /* moving rdi into rdi, but this is a no-op */
            /* moving rsi into rsi, but this is a no-op */
            /* moving rax into rax, but this is a no-op */
            syscall
        >>> print pwnlib.shellcraft.amd64.linux.syscall('rbp', None, None, 1).rstrip()
            /* call syscall('rbp', ?, ?, 1) */
            push 0x1
            pop rdx
            mov rax, rbp
            syscall
</%docstring>
<%
  append_cdq = False
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
% for dst, src in zip(['rdi', 'rsi', 'rdx', 'r10', 'r8', 'r9', 'rax'], [arg0, arg1, arg2, arg3, arg4, arg5, syscall]):
  % if dst == 'rdx' and src == 0:
    <% append_cdq = True %>\
  % elif src != None:
    <%
      if isinstance(src, (str, unicode)):
          src = getattr(constants, src, src)
    %>\
    ${amd64.mov(dst, src)}
  % endif
% endfor
% if append_cdq:
    cdq /* Set rdx to 0, rax is known to be positive */
% endif
    syscall
