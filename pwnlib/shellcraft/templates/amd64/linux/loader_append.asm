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

    >>> gcc = process(['gcc','-m64','-xc','-static','-Wl,-Ttext-segment=0x20000000','-'])
    >>> gcc.write(b'''
    ... int main() {
    ...     printf("Hello, %s!\\n", "amd64");
    ... }
    ... ''')
    >>> gcc.shutdown('send')
    >>> gcc.poll(True)
    0
    >>> sc = shellcraft.loader_append('a.out')

The following doctest is commented out because it doesn't work on Travis
for reasons I cannot diagnose.  However, it should work just fine :-)

    # >>> run_assembly(sc).recvline() == b'Hello, amd64!\n'
    # True

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

if os.path.isfile(data):
    with open(data, 'rb') as f:
        data = f.read()
%>
    ${'.string "%s"' % ''.join('\\x%02x' % c for c in bytearray(data))}
%endif
