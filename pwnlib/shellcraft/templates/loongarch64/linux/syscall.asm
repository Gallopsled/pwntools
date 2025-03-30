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
            addi.d   $a0, $r0, 1
            addi.d   $a1, $sp, 0
            addi.d   $a2, $r0, 2
            addi.d   $a3, $r0, 0
            addi.d   $a7, $r0, 221
            syscall  0
        >>> print(pwnlib.shellcraft.loongarch64.linux.syscall('SYS_execve', 2, 1, 0, 20).rstrip())
            addi.d   $a0, $r0, 2
            addi.d   $a1, $r0, 1
            addi.d   $a2, $r0, 0
            addi.d   $a3, $r0, 20
            addi.d   $a7, $r0, 221
            syscall  0
        >>> print(pwnlib.shellcraft.loongarch64.linux.syscall().rstrip())
            syscall  0
        >>> print(pwnlib.shellcraft.loongarch64.linux.syscall('a7', 'a0', 'a1').rstrip())
            syscall  0
        >>> print(pwnlib.shellcraft.loongarch64.linux.syscall('a3', None, None, 1).rstrip())
            addi.d   $a2, $r0, 1
            addi.d   $a7, $a3, 0
            syscall  0
        >>> print(pwnlib.shellcraft.loongarch64.linux.syscall(
        ...               'SYS_mmap', 0, 0x1000,
        ...               'PROT_READ | PROT_WRITE | PROT_EXEC',
        ...               'MAP_PRIVATE',
        ...               -1, 0).rstrip())
            addi.d   $a0, $r0, 0
            addi.d   $a1, $r0, 1
            lu52i.d  $a1, $a1, 0
            addi.d   $a2, $r0, 7
            addi.d   $a3, $r0, 2
            addi.d   $a4, $r0, 15
            lu52i.d  $a4, $a4, -1
            lu52i.d  $a4, $a4, -1
            lu52i.d  $a4, $a4, -1
            lu52i.d  $a4, $a4, -1
            lu52i.d  $a4, $a4, -1
            addi.d   $a5, $r0, 0
            addi.d   $a7, $r0, 222
            syscall  0
        >>> print(pwnlib.shellcraft.loongarch64.linux.syscall(
        ...               'SYS_mmap', 0, 0x1000,
        ...               'PROT_READ | PROT_WRITE | PROT_EXEC',
        ...               'MAP_PRIVATE',
        ...               -1, 0).rstrip())
            addi.d   $a0, $r0, 0
            addi.d   $a1, $r0, 1
            lu52i.d  $a1, $a1, 0
            addi.d   $a2, $r0, 7
            addi.d   $a3, $r0, 2
            addi.d   $a4, $r0, 15
            lu52i.d  $a4, $a4, -1
            lu52i.d  $a4, $a4, -1
            lu52i.d  $a4, $a4, -1
            lu52i.d  $a4, $a4, -1
            lu52i.d  $a4, $a4, -1
            addi.d   $a5, $r0, 0
            addi.d   $a7, $r0, 222
            syscall  0
        >>> print(pwnlib.shellcraft.loongarch64.openat('AT_FDCWD', '/home/pwn/flag').rstrip())
            /* openat(fd='AT_FDCWD', file='/home/pwn/flag', oflag=0) */
            addi.d   $t8, $r0, 7
            lu52i.d  $t8, $t8, 1904
            lu52i.d  $t8, $t8, 758
            lu52i.d  $t8, $t8, 1389
            lu52i.d  $t8, $t8, 1782
            lu52i.d  $t8, $t8, -2001
            addi.d   $sp, $sp, -8
            st.d     $t8, $sp, 0
            addi.d   $t8, $r0, 1654
            lu52i.d  $t8, $t8, 364
            lu52i.d  $t8, $t8, 1634
            lu52i.d  $t8, $t8, -146
            addi.d   $sp, $sp, -8
            st.d     $t8, $sp, 0
            addi.d   $a1, $sp, 0
            addi.d   $a0, $r0, 15
            lu52i.d  $a0, $a0, -1
            lu52i.d  $a0, $a0, -1
            lu52i.d  $a0, $a0, -1
            lu52i.d  $a0, $a0, -1
            lu52i.d  $a0, $a0, -100
            addi.d   $a2, $r0, 0
            addi.d   $a7, $r0, 56
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
