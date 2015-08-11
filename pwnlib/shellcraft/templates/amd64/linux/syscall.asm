<%
  from pwnlib.shellcraft import amd64
  from pwnlib.constants import Constant
  from pwnlib.abi import linux_amd64_syscall as abi
%>
<%page args="syscall = None, arg0 = None, arg1 = None, arg2 = None, arg3 = None, arg4 = None, arg5 = None"/>
<%docstring>
Args: [syscall_number, \*args]
    Does a syscall

Any of the arguments can be expressions to be evaluated by :func:`pwnlib.constants.eval`.

Example:

        >>> print pwnlib.shellcraft.amd64.linux.syscall('SYS_execve', 1, 'rsp', 2, 0).rstrip()
            /* call execve(1, 'rsp', 2, 0) */
            xor r10d, r10d /* 0 */
            push (SYS_execve) /* 0x3b */
            pop rax
            push 1
            pop rdi
            push 2
            pop rdx
            mov rsi, rsp
            syscall
        >>> print pwnlib.shellcraft.amd64.linux.syscall('SYS_execve', 2, 1, 0, -1).rstrip()
            /* call execve(2, 1, 0, -1) */
            push -1
            pop r10
            push (SYS_execve) /* 0x3b */
            pop rax
            push 2
            pop rdi
            push 1
            pop rsi
            cdq /* rdx=0 */
            syscall
        >>> print pwnlib.shellcraft.amd64.linux.syscall().rstrip()
            /* call syscall() */
            syscall
        >>> print pwnlib.shellcraft.amd64.linux.syscall('rax', 'rdi', 'rsi').rstrip()
            /* call syscall('rax', 'rdi', 'rsi') */
            /* setregs noop */
            syscall
        >>> print pwnlib.shellcraft.amd64.linux.syscall('rbp', None, None, 1).rstrip()
            /* call syscall('rbp', ?, ?, 1) */
            mov rax, rbp
            push 1
            pop rdx
            syscall
        >>> print pwnlib.shellcraft.amd64.linux.syscall(
        ...               'SYS_mmap', 0, 0x1000,
        ...               'PROT_READ | PROT_WRITE | PROT_EXEC',
        ...               'MAP_PRIVATE | MAP_ANONYMOUS',
        ...               -1, 0).rstrip()
            /* call mmap(0, 4096, 'PROT_READ | PROT_WRITE | PROT_EXEC', 'MAP_PRIVATE | MAP_ANONYMOUS', -1, 0) */
            push (MAP_PRIVATE | MAP_ANONYMOUS) /* 0x22 */
            pop r10
            push -1
            pop r8
            xor r9d, r9d /* 0 */
            push (SYS_mmap) /* 9 */
            pop rax
            xor edi, edi /* 0 */
            push (PROT_READ | PROT_WRITE | PROT_EXEC) /* 7 */
            pop rdx
            mov esi, 0x1010101 /* 4096 == 0x1000 */
            xor esi, 0x1011101
            syscall

</%docstring>
<%
  append_cdq = False
  if isinstance(syscall, (str, unicode, Constant)) and str(syscall).startswith('SYS_'):
      syscall_repr = str(syscall)[4:] + "(%s)"
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
%if any(a is not None for a in arguments):
    ${amd64.setregs(regctx)}
%endif
    syscall
