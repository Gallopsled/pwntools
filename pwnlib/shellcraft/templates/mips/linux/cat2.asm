<%
  from pwnlib import constants
  from pwnlib.shellcraft import mips
  from pwnlib.shellcraft import common
%>
<%page args="filename, fd=1, length=0x4000"/>
<%docstring>
Opens a file and writes its contents to the specified file descriptor.
Uses an extra stack buffer and must know the length.

Example:

    >>> f = tempfile.mktemp()
    >>> write(f, 'FLAG')
    >>> sc = shellcraft.mips.linux.cat2(f)
    >>> sc += shellcraft.mips.linux.exit(0)
    >>> run_assembly(sc).recvall()
    b'FLAG'

</%docstring>

    ${mips.pushstr(filename)}
    ${mips.open('$sp', int(constants.O_RDONLY), length)}
    sub $sp, $a2
    ${mips.read('$v0', '$sp', '$a2')}
    ${mips.write(fd, '$sp', '$v0')}
