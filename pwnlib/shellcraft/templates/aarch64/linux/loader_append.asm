<%
    from pwnlib.shellcraft.aarch64.linux import loader
    from pwnlib.shellcraft import common
%>
<%docstring>
Loads a statically-linked ELF into memory and transfers control.

Similar to loader.asm but loads an appended ELF.

Arguments:
    data(str): If a valid filename, the data is loaded from the named file.
               Otherwise, this is treated as raw ELF data to append.
               If ``None``, it is ignored.

Example:

The following doctest is commented out because it doesn't work on Travis
for reasons I cannot diagnose.  However, it should work just fine :-)

    >>> payload = shellcraft.echo(b'Hello, world!\n') + shellcraft.exit(0)
    >>> payloadELF = ELF.from_assembly(payload)
    >>> loader = shellcraft.loader_append(payloadELF.data)
    >>> loaderELF = ELF.from_assembly(loader, vma=0, shared=True)
    >>> loaderELF.process().recvall()
    b'Hello, world!\n'

</%docstring>
<%page args="data = None"/>
<%
there = common.label('there')
here  = common.label('here')
%>
    b ${there}
${here}:
    mov x0, x30 /* lr */
    ${loader('x0')}
${there}:
    bl ${here}
%if data:
<%
import os

if b'\x00' not in data and os.path.isfile(data):
    with open(data, 'rb') as f:
        data = f.read()
%>
    ${'.string "%s"' % ''.join('\\x%02x' % c for c in bytearray(data))}
%endif
