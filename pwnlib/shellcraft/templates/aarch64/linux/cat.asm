<%
  from pwnlib import shellcraft
%>
<%page args="filename, fd=1"/>
<%docstring>
Opens a file and writes its contents to the specified file descriptor.

Example:

    >>> write('flag', 'This is the flag\n')
    >>> shellcode = shellcraft.cat('flag') + shellcraft.exit(0)
    >>> print(disasm(asm(shellcode)))
       0:   d28d8cce        mov     x14, #0x6c66                    // #27750
       4:   f2acec2e        movk    x14, #0x6761, lsl #16
       8:   f81f0fee        str     x14, [sp, #-16]!
       c:   d29ff380        mov     x0, #0xff9c                     // #65436
      10:   f2bfffe0        movk    x0, #0xffff, lsl #16
      14:   f2dfffe0        movk    x0, #0xffff, lsl #32
      18:   f2ffffe0        movk    x0, #0xffff, lsl #48
      1c:   910003e1        mov     x1, sp
      20:   aa1f03e2        mov     x2, xzr
      24:   aa1f03e3        mov     x3, xzr
      28:   d2800708        mov     x8, #0x38                       // #56
      2c:   d4000001        svc     #0x0
      30:   aa0003e1        mov     x1, x0
      34:   d2800020        mov     x0, #0x1                        // #1
      38:   aa1f03e2        mov     x2, xzr
      3c:   d29fffe3        mov     x3, #0xffff                     // #65535
      40:   f2afffe3        movk    x3, #0x7fff, lsl #16
      44:   d28008e8        mov     x8, #0x47                       // #71
      48:   d4000001        svc     #0x0
      4c:   aa1f03e0        mov     x0, xzr
      50:   d2800ba8        mov     x8, #0x5d                       // #93
      54:   d4000001        svc     #0x0
    >>> run_assembly(shellcode).recvline()
    'This is the flag\n'
</%docstring>
<%
if fd == 'x0':
  raise Exception("File descriptor cannot be x0, it will be overwritten")
%>
    ${shellcraft.open(filename)}
    ${shellcraft.syscall('SYS_sendfile', fd, 'x0', 0, 0x7fffffff)}
