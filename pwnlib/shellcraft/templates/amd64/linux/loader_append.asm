<%
    from pwnlib.shellcraft.amd64.linux import loader
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

    >>> payload = shellcraft.echo(b'Hello, world!\n') + shellcraft.exit(0)
    >>> payloadELF = ELF.from_assembly(payload)
    >>> payloadELF.arch
    'amd64'
    >>> loader = shellcraft.loader_append(payloadELF.data)
    >>> loaderELF = ELF.from_assembly(loader, vma=0, shared=True)
    >>> loaderELF.process().recvall()
    b'Hello, world!\n'


</%docstring>
<%page args="data = None"/>
<%
elf_data = common.label('elf_data')
load = common.label('load')
%>
    jmp ${elf_data}
${load}:
    pop rax
    ${loader('rax')}
${elf_data}:
    call ${load}
%if data:
<%
import os

if b'\x00' not in data and os.path.isfile(data):
    with open(data, 'rb') as f:
        data = f.read()
%>
    ${'.string "%s"' % ''.join('\\x%02x' % c for c in bytearray(data))}
%endif
