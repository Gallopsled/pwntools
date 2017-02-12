<%
  import pwnlib.shellcraft as sc
  from pwnlib.shellcraft import common
%>
<%page args="filename, fd=1"/>
<%docstring>
Opens a file and writes its contents to the specified file descriptor.

Example:

    >>> f = tempfile.mktemp()
    >>> write(f, 'FLAG')
    >>> run_assembly(shellcraft.i386.linux.cat(f)).recvall()
    'FLAG'

</%docstring>
<%
label = common.label("sendfile_loop")
%>

    ${sc.pushstr(filename)}
    ${sc.open('esp', 0, 'O_RDONLY')}
    ${sc.sendfile(fd, 'eax', 0, 0x7fffffff)}
