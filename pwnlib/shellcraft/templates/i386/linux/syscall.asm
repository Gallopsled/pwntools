<%
  from pwnlib.shellcraft import i386, pretty
  from pwnlib.constants import Constant
  from pwnlib.abi import linux_i386_syscall as abi
%>
<%page args="syscall = None, arg0 = None, arg1 = None, arg2 = None, arg3 = None, arg4 = None, arg5 = None"/>
<%docstring>
Args: [syscall_number, \*args]
    Does a syscall

Any of the arguments can be expressions to be evaluated by :func:`pwnlib.constants.eval`.

Example:

        >>> print pwnlib.shellcraft.i386.linux.syscall('SYS_execve', 1, 'esp', 2, 0).rstrip()
            /* call execve(1, 'esp', 2, 0) */
            push (SYS_execve) /* 0xb */
            pop eax
            push 1
            pop ebx
            mov ecx, esp
            push 2
            pop edx
            xor esi, esi
            int 0x80
        >>> print pwnlib.shellcraft.i386.linux.syscall('SYS_execve', 2, 1, 0, 20).rstrip()
            /* call execve(2, 1, 0, 0x14) */
            push (SYS_execve) /* 0xb */
            pop eax
            push 2
            pop ebx
            push 1
            pop ecx
            push 0x14
            pop esi
            cdq /* edx=0 */
            int 0x80
        >>> print pwnlib.shellcraft.i386.linux.syscall().rstrip()
            /* call syscall() */
            int 0x80
        >>> print pwnlib.shellcraft.i386.linux.syscall('eax', 'ebx', 'ecx').rstrip()
            /* call syscall('eax', 'ebx', 'ecx') */
            /* setregs noop */
            int 0x80
        >>> print pwnlib.shellcraft.i386.linux.syscall('ebp', None, None, 1).rstrip()
            /* call syscall('ebp', ?, ?, 1) */
            mov eax, ebp
            push 1
            pop edx
            int 0x80
        >>> print pwnlib.shellcraft.i386.linux.syscall(
        ...               'SYS_mmap2', 0, 0x1000,
        ...               'PROT_READ | PROT_WRITE | PROT_EXEC',
        ...               'MAP_PRIVATE | MAP_ANONYMOUS',
        ...               -1, 0).rstrip()
            /* call mmap2(0, 0x1000, 'PROT_READ | PROT_WRITE | PROT_EXEC', 'MAP_PRIVATE | MAP_ANONYMOUS', -1, 0) */
            xor eax, eax
            mov al, 0xc0
            xor ebp, ebp
            xor ebx, ebx
            xor ecx, ecx
            mov ch, 0x1000 >> 8
            push -1
            pop edi
            push (PROT_READ | PROT_WRITE | PROT_EXEC) /* 7 */
            pop edx
            push (MAP_PRIVATE | MAP_ANONYMOUS) /* 0x22 */
            pop esi
            int 0x80
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
          args.append(pretty(arg, False))
  while args and args[-1] == '?':
      args.pop()
  syscall_repr = syscall_repr % ', '.join(args)

  registers = abi.register_arguments
  arguments = [syscall, arg0, arg1, arg2, arg3, arg4, arg5]
  regctx    = dict(zip(registers, arguments))
%>\
    /* call ${syscall_repr} */
%if any(a is not None for a in arguments):
    ${i386.setregs(regctx)}
%endif
    int 0x80
