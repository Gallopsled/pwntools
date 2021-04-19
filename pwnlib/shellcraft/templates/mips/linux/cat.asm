<%
  from pwnlib import constants
  from pwnlib.shellcraft import mips
  from pwnlib.shellcraft import common
%>
<%page args="filename, fd=1"/>
<%docstring>
Opens a file and writes its contents to the specified file descriptor.

Example:

    >>> f = tempfile.mktemp()
    >>> write(f, 'FLAG')
    >>> sc = shellcraft.mips.linux.cat(f)
    >>> sc += shellcraft.mips.linux.exit(0)
    >>> run_assembly(sc).recvall()
    b'FLAG'

</%docstring>
<%
label = common.label("sendfile_loop")
%>

    ${mips.pushstr(filename)}
    ${mips.open('$sp', int(constants.O_RDONLY), 0)}
    ${mips.sendfile(fd, '$v0', 0, 0x7fffffff)}
