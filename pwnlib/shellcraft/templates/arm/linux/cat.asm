<%
  from pwnlib import constants
  from pwnlib.shellcraft import arm
%>
<%page args="filename, fd=1"/>
<%docstring>
Opens a file and writes its contents to the specified file descriptor.

Example:

    >>> f = tempfile.mktemp()
    >>> write(f, 'FLAG\n')
    >>> run_assembly(shellcraft.arm.linux.cat(f)).recvline()
    b'FLAG\n'

</%docstring>
    ${arm.pushstr(filename)}
    ${arm.linux.open('sp', int(constants.O_RDONLY), 0)}
    ${arm.linux.sendfile(fd, 'r0', 0, 0x7fffffff)}
