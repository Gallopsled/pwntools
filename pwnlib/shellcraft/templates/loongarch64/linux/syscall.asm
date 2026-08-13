<%
  from pwnlib.shellcraft import loongarch64, pretty
  from pwnlib.constants import Constant
  from pwnlib.abi import linux_loongarch64_syscall as abi
%>
<%page args="syscall = None, arg0 = None, arg1 = None, arg2 = None, arg3 = None, arg4=None, arg5=None"/>
<%docstring>
Args: [syscall_number, \*args]
    Does a syscall

Any of the arguments can be expressions to be evaluated by :func:`pwnlib.constants.eval`.

Example:

        >>> print(pwnlib.shellcraft.loongarch64.linux.syscall('SYS_execve', 1, 'sp', 2, 0).rstrip())
            li.d     $a0, 1
            move     $a1, $sp
            li.d     $a2, 2
            li.d     $a3, 0
            li.d     $a7, 221
            syscall  0
        >>> print(pwnlib.shellcraft.loongarch64.linux.syscall('SYS_execve', 2, 1, 0, 20).rstrip())
            li.d     $a0, 2
            li.d     $a1, 1
            li.d     $a2, 0
            li.d     $a3, 20
            li.d     $a7, 221
            syscall  0
        >>> print(pwnlib.shellcraft.loongarch64.linux.syscall().rstrip())
            syscall  0
        >>> print(pwnlib.shellcraft.loongarch64.linux.syscall('a7', 'a0', 'a1').rstrip())
            syscall  0
        >>> print(pwnlib.shellcraft.loongarch64.linux.syscall('a3', None, None, 1).rstrip())
            li.d     $a2, 1
            move     $a7, $a3
            syscall  0
        >>> print(pwnlib.shellcraft.loongarch64.linux.syscall(
        ...               'SYS_mmap', 0, 0x1000,
        ...               'PROT_READ | PROT_WRITE | PROT_EXEC',
        ...               'MAP_PRIVATE',
        ...               -1, 0).rstrip())
            li.d     $a0, 0
            li.d     $a1, 4096
            li.d     $a2, 7
            li.d     $a3, 2
            li.d     $a4, 18446744073709551615
            li.d     $a5, 0
            li.d     $a7, 222
            syscall  0
        >>> print(pwnlib.shellcraft.loongarch64.linux.syscall(
        ...               'SYS_mmap', 0, 0x1000,
        ...               'PROT_READ | PROT_WRITE | PROT_EXEC',
        ...               'MAP_PRIVATE',
        ...               -1, 0).rstrip())
            li.d     $a0, 0
            li.d     $a1, 4096
            li.d     $a2, 7
            li.d     $a3, 2
            li.d     $a4, 18446744073709551615
            li.d     $a5, 0
            li.d     $a7, 222
            syscall  0
        >>> print(pwnlib.shellcraft.loongarch64.openat('AT_FDCWD', '/home/pwn/flag').rstrip())
            /* openat(fd='AT_FDCWD', file='/home/pwn/flag', oflag=0) */
            li.d     $t8, 8606431000579237935
            addi.d   $sp, $sp, -8
            st.d     $t8, $sp, 0
            li.d     $t8, 113668128124782
            addi.d   $sp, $sp, -8
            st.d     $t8, $sp, 0
            move     $a1, $sp
            li.d     $a0, 18446744073709551516
            li.d     $a2, 0
            li.d     $a7, 56
            syscall  0
</%docstring>
<%
  registers = abi.register_arguments
  arguments = [syscall, arg0, arg1, arg2, arg3, arg4, arg5]
  regctx    = dict(zip(registers, arguments))
%>\
%if any(a is not None for a in arguments):
${loongarch64.setregs(regctx)}
%endif
    syscall  0
