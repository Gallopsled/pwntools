<%
  from pwnlib.shellcraft.amd64 import syscall, pushstr
  from pwnlib.shellcraft import common
%>
<%page args="filename, fd=1"/>
<%docstring>
Opens a file and writes its contents to the specified file descriptor.
</%docstring>

    ${pushstr(filename)}
    ${syscall('SYS_open', 'rsp', 0, 'O_RDONLY')}
    ${syscall('SYS_sendfile', fd, 'rax', 0, 0x7fffffff)}