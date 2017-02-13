<%
  from pwnlib import shellcraft
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
      10:   d29ff380        mov     x0, #0xff9c                     // #65436
      14:   f2bfffe0        movk    x0, #0xffff, lsl #16
      18:   f2dfffe0        movk    x0, #0xffff, lsl #32
      1c:   f2ffffe0        movk    x0, #0xffff, lsl #48
      20:   910003e1        mov     x1, sp
      24:   aa1f03e2        mov     x2, xzr
      28:   aa1f03e3        mov     x3, xzr
      2c:   d2800708        mov     x8, #0x38                       // #56
      30:   d4000001        svc     #0x0
      34:   aa0003e1        mov     x1, x0
      38:   d2800020        mov     x0, #0x1                        // #1
      3c:   aa1f03e2        mov     x2, xzr
      40:   d29fffe3        mov     x3, #0xffff                     // #65535
      44:   f2afffe3        movk    x3, #0x7fff, lsl #16
      48:   d28008e8        mov     x8, #0x47                       // #71
      4c:   d4000001        svc     #0x0
      50:   aa1f03e0        mov     x0, xzr
      54:   d2800ba8        mov     x8, #0x5d                       // #93
      58:   d4000001        svc     #0x0
    >>> run_assembly(shellcode).recvline()
    'This is the flag\n'
</%docstring>
<%
if fd == 'x0':
  raise Exception("File descriptor cannot be x0, it will be overwritten")
%>
    ${shellcraft.open(filename)}
    ${shellcraft.syscall('SYS_sendfile', fd, 'x0', 0, 0x7fffffff)}
