<%
  from pwnlib.shellcraft import amd64, pretty
  from pwnlib.constants import Constant
  from pwnlib.abi import freebsd_amd64_syscall as abi
  from six import text_type
%>
<%page args="syscall = None, arg0 = None, arg1 = None, arg2 = None, arg3 = None, arg4 = None, arg5 = None"/>
<%docstring>
Args: [syscall_number, \*args]
    Does a syscall

Any of the arguments can be expressions to be evaluated by :func:`pwnlib.constants.eval`.

Example:

        >>> print(pwnlib.shellcraft.amd64.freebsd.syscall('SYS_execve', 1, 'rsp', 2, 0).rstrip())
            /* call execve(1, 'rsp', 2, 0) */
            push SYS_execve /* 0x3b */
            pop rax
            xor ecx, ecx /* 0 */
            push 1
            pop rdi
            push 2
            pop rdx
            mov rsi, rsp
            syscall
        >>> print(pwnlib.shellcraft.amd64.freebsd.syscall('SYS_execve', 2, 1, 0, -1).rstrip())
            /* call execve(2, 1, 0, -1) */
            push SYS_execve /* 0x3b */
            pop rax
            push -1
            pop rcx
            push 2
            pop rdi
            push 1
            pop rsi
            cdq /* rdx=0 */
            syscall
        >>> print(pwnlib.shellcraft.amd64.freebsd.syscall().rstrip())
            /* call syscall() */
            /* setregs noop */
            syscall
        >>> print(pwnlib.shellcraft.amd64.freebsd.syscall('rax', 'rdi', 'rsi').rstrip())
            /* call syscall('rax', 'rdi', 'rsi') */
            /* setregs noop */
            syscall
        >>> print(pwnlib.shellcraft.amd64.freebsd.syscall('rbp', None, None, 1).rstrip())
            /* call syscall('rbp', ?, ?, 1) */
            mov rax, rbp
            push 1
            pop rdi
            syscall
        >>> print(pwnlib.shellcraft.amd64.freebsd.syscall(
        ...               'SYS_mmap', 0, 0x1000,
        ...               'PROT_READ | PROT_WRITE | PROT_EXEC',
        ...               'MAP_PRIVATE | MAP_ANONYMOUS',
        ...               -1, 0).rstrip())
            /* call mmap(0, 0x1000, 'PROT_READ | PROT_WRITE | PROT_EXEC', 'MAP_PRIVATE | MAP_ANONYMOUS', -1, 0) */
            push -1
            pop r8
            xor r9d, r9d /* 0 */
            xor eax, eax
            mov ax, SYS_mmap /* 0x1dd */
            xor ecx, ecx
            mov cx, (MAP_PRIVATE | MAP_ANONYMOUS) /* 0x1002 */
            xor edi, edi /* 0 */
            push (PROT_READ | PROT_WRITE | PROT_EXEC) /* 7 */
            pop rdx
            mov esi, 0x1010101 /* 4096 == 0x1000 */
            xor esi, 0x1011101
            syscall
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
    ${amd64.setregs(regctx)}
%for arg in stack_args:
    ${amd64.push(arg)}
%endfor
    syscall
