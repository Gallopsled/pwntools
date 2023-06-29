<%
  from pwnlib import constants
  from pwnlib.shellcraft import arm
%>
<%page args="filename, fd=1, length=0x4000"/>
<%docstring>
Opens a file and writes its contents to the specified file descriptor.
Uses an extra stack buffer and must know the length.

Example:

    >>> f = tempfile.mktemp()
    >>> write(f, 'FLAG\n')
    >>> run_assembly(shellcraft.arm.linux.cat2(f)).recvline()
    b'FLAG\n'

</%docstring>
    ${arm.pushstr(filename)}
    ${arm.linux.open('sp', int(constants.O_RDONLY), length)}
    sub sp, r2
    ${arm.linux.read('r0', 'sp', 'r2')}
    ${arm.linux.write(fd, 'sp', 'r0')}
