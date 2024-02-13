<%
  from pwnlib import shellcraft
%>
<%page args="filename, fd=1, length=0x4000"/>
<%docstring>
Opens a file and writes its contents to the specified file descriptor.
Uses an extra stack buffer and must know the length.

Example:

    >>> f = tempfile.mktemp()
    >>> write(f, 'This is the flag\n')
    >>> shellcode = shellcraft.cat2(f) + shellcraft.exit(0)
    >>> run_assembly(shellcode).recvline()
    b'This is the flag\n'
</%docstring>
<%
if fd == 'x0':
  raise Exception("File descriptor cannot be x0, it will be overwritten")
%>
    ${shellcraft.open(filename)}
    ${shellcraft.mov('x2', length)}
    sub sp, sp, x2
    ${shellcraft.read('x0', 'sp', 'x2')}
    ${shellcraft.write(fd, 'sp', 'x0')}
