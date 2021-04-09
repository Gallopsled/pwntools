<%
  from pwnlib import shellcraft
%>
<%page args="filename, fd=1"/>
<%docstring>
Opens a file and writes its contents to the specified file descriptor.

Example:

    >>> f = tempfile.mktemp()
    >>> write(f, 'This is the flag\n')
    >>> shellcode = shellcraft.cat(f) + shellcraft.exit(0)
    >>> run_assembly(shellcode).recvline()
    b'This is the flag\n'
</%docstring>
<%
if fd == 'x0':
  raise Exception("File descriptor cannot be x0, it will be overwritten")
%>
    ${shellcraft.open(filename)}
    ${shellcraft.syscall('SYS_sendfile', fd, 'x0', 0, 0x7fffffff)}
