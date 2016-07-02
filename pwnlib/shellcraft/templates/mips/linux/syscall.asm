<%
  from pwnlib.shellcraft import mips, pretty
  from pwnlib.constants import Constant
  from pwnlib.abi import linux_mips_syscall as abi
%>
<%page args="syscall = None, arg0 = None, arg1 = None, arg2 = None, arg3 = None, arg4=None, arg5=None"/>
<%docstring>
Args: [syscall_number, \*args]
    Does a syscall

Any of the arguments can be expressions to be evaluated by :func:`pwnlib.constants.eval`.

Example:

        >>> print pwnlib.shellcraft.i386.linux.syscall('SYS_execve', 1, 'esp', 2, 0).rstrip()
            /* call execve(1, 'esp', 2, 0) */
            push 0x1
            pop ebx
            mov ecx, esp
            push 0x2
            pop edx
            xor esi, esi
            push 0xb
            pop eax
            int 0x80
        >>> print pwnlib.shellcraft.i386.linux.syscall('SYS_execve', 2, 1, 0, 20).rstrip()
            /* call execve(2, 1, 0, 20) */
            push 0x2
            pop ebx
            push 0x1
            pop ecx
            push 0x14
            pop esi
            push 0xb
            pop eax
            cdq /* Set edx to 0, eax is known to be positive */
            int 0x80
        >>> print pwnlib.shellcraft.i386.linux.syscall().rstrip()
            /* call syscall() */
            int 0x80
        >>> print pwnlib.shellcraft.i386.linux.syscall('eax', 'ebx', 'ecx').rstrip()
            /* call syscall('eax', 'ebx', 'ecx') */
            /* moving ebx into ebx, but this is a no-op */
            /* moving ecx into ecx, but this is a no-op */
            /* moving eax into eax, but this is a no-op */
            int 0x80
        >>> print pwnlib.shellcraft.i386.linux.syscall('ebp', None, None, 1).rstrip()
            /* call syscall('ebp', ?, ?, 1) */
            push 0x1
            pop edx
            mov eax, ebp
            int 0x80
        >>> print pwnlib.shellcraft.i386.linux.syscall(
        ...               'SYS_mmap2', 0, 0x1000,
        ...               'PROT_READ | PROT_WRITE | PROT_EXEC',
        ...               'MAP_PRIVATE | MAP_ANONYMOUS',
        ...               -1, 0).rstrip()
            /* call mmap2(0, 4096, 'PROT_READ | PROT_WRITE | PROT_EXEC', 'MAP_PRIVATE | MAP_ANONYMOUS', -1, 0) */
            xor ebx, ebx
            xor ecx, ecx
            mov ch, 0x10
            push 0x7
            pop edx
            push 0x22
            pop esi
            push -1
            pop edi
            xor ebp, ebp
            xor eax, eax
            mov al, 0xc0
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
    ${mips.setregs(regctx)}
%endif
    syscall 0x40404
