<%
import six
from pwnlib.shellcraft.i386 import push
from pwnlib.shellcraft.i386.linux import read, readn, mmap
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
    ${read(fd, 'esp', 4)}
    pop  eax
    push eax /* Save exact size */
%else:
    ${push(length)}
%endif

    /* Page-align */
    shr  eax, 12
    inc  eax
    shl  eax, 12

    /* Map it */
    ${mmap(0, 'eax', protection, flags, 0, 0)}

    /* Grab the saved size, save the address */
    pop  ebx
    push eax

    /* Read in all of the data */
    ${readn(fd, 'eax', 'ebx')}

    /* Go to shellcode */
    ret
