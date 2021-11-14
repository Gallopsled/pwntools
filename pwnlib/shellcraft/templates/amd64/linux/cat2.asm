<%
  from pwnlib.shellcraft.amd64 import syscall, pushstr
  from pwnlib.shellcraft import common
%>
<%page args="filename, fd=1, length=0x4000"/>
<%docstring>
Opens a file and writes its contents to the specified file descriptor.
Uses an extra stack buffer and must know the length.
</%docstring>

    ${pushstr(filename)}
    ${syscall('SYS_open', 'rsp', 'O_RDONLY', length)}
    sub rsp, rdx
    ${syscall('SYS_read', 'rax', 'rsp', 'rdx')}
    ${syscall('SYS_write', fd, 'rsp', 'rax')}
