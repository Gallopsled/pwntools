<%
  from pwnlib.shellcraft.aarch64 import syscall, pushstr
  from pwnlib.shellcraft import common
%>
<%page args="filename, fd=1"/>
<%docstring>
Opens a file and writes its contents to the specified file descriptor.

Example:

    >>> write('flag', 'This is the flag\n')
    >>> run_assembly(shellcraft.cat('flag')).recvline()
    'This is the flag\n'
</%docstring>

    ${pushstr(filename)}
    ${syscall('SYS_open', 'sp', 0, 'O_RDONLY')}
    ${syscall('SYS_sendfile', fd, 'x0', 0, 0x7fffffff)}
