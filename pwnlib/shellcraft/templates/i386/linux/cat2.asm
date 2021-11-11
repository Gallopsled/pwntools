<%
  import pwnlib.shellcraft as sc
  from pwnlib.shellcraft import common
%>
<%page args="filename, fd=1, length=0x4000"/>
<%docstring>
Opens a file and writes its contents to the specified file descriptor.
Uses an extra stack buffer and must know the length.

Example:

    >>> f = tempfile.mktemp()
    >>> write(f, 'FLAG')
    >>> run_assembly(shellcraft.i386.linux.cat2(f)).recvall()
    b'FLAG'

</%docstring>

    ${sc.pushstr(filename)}
    ${sc.open('esp', 'O_RDONLY', length)}
    sub esp, edx
    ${sc.read('eax', 'esp', 'edx')}
    ${sc.write(fd, 'esp', 'eax')}
