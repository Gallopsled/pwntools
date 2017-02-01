<%
  from pwnlib.shellcraft.aarch64 import syscall, pushstr
  from pwnlib.shellcraft import common
%>
<%page args="filename, fd=1"/>
<%docstring>
Opens a file and writes its contents to the specified file descriptor.

Example:

    >>> write('flag', 'This is the flag\n')
    >>> shellcode = shellcraft.cat('flag') + shellcraft.exit(0)
    >>> print disasm(asm(shellcode))
       0:   d10043ff        sub     sp, sp, #0x10
       4:   d28d8cc0        mov     x0, #0x6c66                     // #27750
       8:   f2acec20        movk    x0, #0x6761, lsl #16
       c:   f80003e0        stur    x0, [sp]
      10:   910003e0        mov     x0, sp
      14:   aa1f03e1        mov     x1, xzr
      18:   aa1f03e2        mov     x2, xzr
      1c:   d2808008        mov     x8, #0x400                      // #1024
      20:   d4000001        svc     #0x0
      24:   aa0003e1        mov     x1, x0
      28:   d2800020        mov     x0, #0x1                        // #1
      2c:   aa1f03e2        mov     x2, xzr
      30:   d29fffe3        mov     x3, #0xffff                     // #65535
      34:   f2afffe3        movk    x3, #0x7fff, lsl #16
      38:   d28008e8        mov     x8, #0x47                       // #71
      3c:   d4000001        svc     #0x0
      40:   aa1f03e0        mov     x0, xzr
      44:   d2800ba8        mov     x8, #0x5d                       // #93
      48:   d4000001        svc     #0x0
    >>> run_assembly(shellcode).recvline()
    'This is the flag\n'
</%docstring>

    ${pushstr(filename)}
    ${syscall('SYS_open', 'sp', 0, 'O_RDONLY')}
    ${syscall('SYS_sendfile', fd, 'x0', 0, 0x7fffffff)}
