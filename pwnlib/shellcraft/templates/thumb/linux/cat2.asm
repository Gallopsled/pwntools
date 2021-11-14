<%
  from pwnlib import constants
  from pwnlib.shellcraft import thumb
  from pwnlib.shellcraft import common
%>
<%page args="filename, fd=1, length=0x4000"/>
<%docstring>
Opens a file and writes its contents to the specified file descriptor.
Uses an extra stack buffer and must know the length.

Example:

    >>> f = tempfile.mktemp()
    >>> write(f, 'FLAG\n')
    >>> run_assembly(shellcraft.arm.to_thumb()+shellcraft.thumb.linux.cat2(f)).recvline()
    b'FLAG\n'

</%docstring>

    ${thumb.pushstr(filename)}
    ${thumb.linux.open('sp', constants.O_RDONLY, length)}
    sub sp, r2
    ${thumb.linux.read('r0', 'sp', 'r2')}
    ${thumb.linux.write(fd, 'sp', 'r0')}
