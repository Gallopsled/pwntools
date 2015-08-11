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
    >>> run_assembly(shellcraft.mips.linux.cat(f)).recvall()
    'FLAG'

</%docstring>
<%
label = common.label("sendfile_loop")
%>

    ${mips.pushstr(filename)}
    ${mips.open('$sp', 0, int(constants.O_RDONLY))}
    ${mips.sendfile(fd, '$v0', 0, 0x7fffffff)}
