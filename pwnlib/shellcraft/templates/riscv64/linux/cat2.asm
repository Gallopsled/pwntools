<%
  from pwnlib.shellcraft.riscv64 import open, syscall, mov
  from pwnlib.shellcraft import common
%>
<%page args="filename, fd=1, length=0x4000"/>
<%docstring>
Opens a file and writes its contents to the specified file descriptor.
Uses an extra stack buffer and must know the length.
</%docstring>

    ${open(filename)}
    ${mov('a2', length)}
    sub sp, sp, a2
    ${syscall('SYS_read', 'a0', 'sp', 'a2')}
    ${syscall('SYS_write', fd, 'sp', 'a0')}
