<%
  from pwnlib import constants
  from pwnlib.shellcraft import thumb
  from pwnlib.shellcraft import common
%>
<%page args="filename, fd=1"/>
<%docstring>
Opens a file and writes its contents to the specified file descriptor.

Example:

    >>> f = tempfile.mktemp()
    >>> write(f, 'FLAG\n')
    >>> run_assembly(shellcraft.arm.to_thumb()+shellcraft.thumb.linux.cat(f)).recvline()
    'FLAG\n'

</%docstring>
<%
label = common.label("sendfile_loop")
%>

    ${thumb.pushstr(filename)}
    ${thumb.linux.open('sp', 0, constants.O_RDONLY)}
    ${thumb.mov('r5', 'r0')}
    ${thumb.linux.sendfile(fd, 'r5', 0, 0x7fffffff)}
